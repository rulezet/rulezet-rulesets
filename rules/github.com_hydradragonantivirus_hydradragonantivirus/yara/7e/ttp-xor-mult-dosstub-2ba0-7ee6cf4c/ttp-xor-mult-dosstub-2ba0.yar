rule TTP_XOR_MULT_DOSStub_2ba0 {
  strings:
    $key_2ba0 = { 7f c8 [2] 0b d0 [2] 4c d2 [2] 0b c3 [2] 45 cf [2] 49 c5 [2] 5e ce [2] 45 80 [2] 78 }

  condition:
    any of them
}