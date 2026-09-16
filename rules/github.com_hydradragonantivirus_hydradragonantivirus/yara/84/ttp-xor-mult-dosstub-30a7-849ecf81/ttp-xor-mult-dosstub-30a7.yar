rule TTP_XOR_MULT_DOSStub_30a7 {
  strings:
    $key_30a7 = { 64 cf [2] 10 d7 [2] 57 d5 [2] 10 c4 [2] 5e c8 [2] 52 c2 [2] 45 c9 [2] 5e 87 [2] 63 }

  condition:
    any of them
}