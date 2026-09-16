rule TTP_XOR_MULT_DOSStub_4aa0 {
  strings:
    $key_4aa0 = { 1e c8 [2] 6a d0 [2] 2d d2 [2] 6a c3 [2] 24 cf [2] 28 c5 [2] 3f ce [2] 24 80 [2] 19 }

  condition:
    any of them
}