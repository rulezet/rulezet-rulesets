rule TTP_XOR_MULT_DOSStub_6ba0 {
  strings:
    $key_6ba0 = { 3f c8 [2] 4b d0 [2] 0c d2 [2] 4b c3 [2] 05 cf [2] 09 c5 [2] 1e ce [2] 05 80 [2] 38 }

  condition:
    any of them
}