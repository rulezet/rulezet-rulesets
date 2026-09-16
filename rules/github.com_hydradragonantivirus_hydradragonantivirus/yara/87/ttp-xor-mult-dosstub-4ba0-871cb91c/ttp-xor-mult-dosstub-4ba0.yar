rule TTP_XOR_MULT_DOSStub_4ba0 {
  strings:
    $key_4ba0 = { 1f c8 [2] 6b d0 [2] 2c d2 [2] 6b c3 [2] 25 cf [2] 29 c5 [2] 3e ce [2] 25 80 [2] 18 }

  condition:
    any of them
}