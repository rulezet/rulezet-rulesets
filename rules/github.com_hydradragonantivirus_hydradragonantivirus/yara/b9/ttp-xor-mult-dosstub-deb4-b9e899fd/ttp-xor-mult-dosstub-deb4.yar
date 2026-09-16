rule TTP_XOR_MULT_DOSStub_deb4 {
  strings:
    $key_deb4 = { 8a dc [2] fe c4 [2] b9 c6 [2] fe d7 [2] b0 db [2] bc d1 [2] ab da [2] b0 94 [2] 8d }

  condition:
    any of them
}