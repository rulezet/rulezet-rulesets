rule TTP_XOR_MULT_DOSStub_21b2 {
  strings:
    $key_21b2 = { 75 da [2] 01 c2 [2] 46 c0 [2] 01 d1 [2] 4f dd [2] 43 d7 [2] 54 dc [2] 4f 92 [2] 72 }

  condition:
    any of them
}