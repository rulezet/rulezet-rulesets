rule TTP_XOR_MULT_DOSStub_55b2 {
  strings:
    $key_55b2 = { 01 da [2] 75 c2 [2] 32 c0 [2] 75 d1 [2] 3b dd [2] 37 d7 [2] 20 dc [2] 3b 92 [2] 06 }

  condition:
    any of them
}