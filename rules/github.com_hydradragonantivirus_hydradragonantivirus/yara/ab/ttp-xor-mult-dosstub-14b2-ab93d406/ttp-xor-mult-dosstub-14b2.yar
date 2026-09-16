rule TTP_XOR_MULT_DOSStub_14b2 {
  strings:
    $key_14b2 = { 40 da [2] 34 c2 [2] 73 c0 [2] 34 d1 [2] 7a dd [2] 76 d7 [2] 61 dc [2] 7a 92 [2] 47 }

  condition:
    any of them
}