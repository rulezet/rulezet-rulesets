rule TTP_XOR_MULT_DOSStub_deb2 {
  strings:
    $key_deb2 = { 8a da [2] fe c2 [2] b9 c0 [2] fe d1 [2] b0 dd [2] bc d7 [2] ab dc [2] b0 92 [2] 8d }

  condition:
    any of them
}