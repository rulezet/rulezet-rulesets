rule TTP_XOR_MULT_DOSStub_47b2 {
  strings:
    $key_47b2 = { 13 da [2] 67 c2 [2] 20 c0 [2] 67 d1 [2] 29 dd [2] 25 d7 [2] 32 dc [2] 29 92 [2] 14 }

  condition:
    any of them
}