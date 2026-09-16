rule TTP_XOR_MULT_DOSStub_04b2 {
  strings:
    $key_04b2 = { 50 da [2] 24 c2 [2] 63 c0 [2] 24 d1 [2] 6a dd [2] 66 d7 [2] 71 dc [2] 6a 92 [2] 57 }

  condition:
    any of them
}