rule TTP_XOR_MULT_DOSStub_13a0 {
  strings:
    $key_13a0 = { 47 c8 [2] 33 d0 [2] 74 d2 [2] 33 c3 [2] 7d cf [2] 71 c5 [2] 66 ce [2] 7d 80 [2] 40 }

  condition:
    any of them
}