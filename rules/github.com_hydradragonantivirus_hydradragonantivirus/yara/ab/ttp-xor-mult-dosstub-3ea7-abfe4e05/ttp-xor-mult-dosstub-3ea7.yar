rule TTP_XOR_MULT_DOSStub_3ea7 {
  strings:
    $key_3ea7 = { 6a cf [2] 1e d7 [2] 59 d5 [2] 1e c4 [2] 50 c8 [2] 5c c2 [2] 4b c9 [2] 50 87 [2] 6d }

  condition:
    any of them
}