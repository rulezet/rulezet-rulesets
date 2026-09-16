rule TTP_XOR_MULT_DOSStub_deb3 {
  strings:
    $key_deb3 = { 8a db [2] fe c3 [2] b9 c1 [2] fe d0 [2] b0 dc [2] bc d6 [2] ab dd [2] b0 93 [2] 8d }

  condition:
    any of them
}