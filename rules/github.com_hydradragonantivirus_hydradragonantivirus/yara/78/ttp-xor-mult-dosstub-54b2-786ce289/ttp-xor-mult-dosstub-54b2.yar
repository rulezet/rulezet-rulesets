rule TTP_XOR_MULT_DOSStub_54b2 {
  strings:
    $key_54b2 = { 00 da [2] 74 c2 [2] 33 c0 [2] 74 d1 [2] 3a dd [2] 36 d7 [2] 21 dc [2] 3a 92 [2] 07 }

  condition:
    any of them
}