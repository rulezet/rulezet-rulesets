rule TTP_XOR_MULT_DOSStub_66b2 {
  strings:
    $key_66b2 = { 32 da [2] 46 c2 [2] 01 c0 [2] 46 d1 [2] 08 dd [2] 04 d7 [2] 13 dc [2] 08 92 [2] 35 }

  condition:
    any of them
}