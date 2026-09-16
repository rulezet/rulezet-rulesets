rule TTP_XOR_MULT_DOSStub_0ea7 {
  strings:
    $key_0ea7 = { 5a cf [2] 2e d7 [2] 69 d5 [2] 2e c4 [2] 60 c8 [2] 6c c2 [2] 7b c9 [2] 60 87 [2] 5d }

  condition:
    any of them
}