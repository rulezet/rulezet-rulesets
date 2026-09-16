rule TTP_XOR_MULT_DOSStub_73b3 {
  strings:
    $key_73b3 = { 27 db [2] 53 c3 [2] 14 c1 [2] 53 d0 [2] 1d dc [2] 11 d6 [2] 06 dd [2] 1d 93 [2] 20 }

  condition:
    any of them
}