rule TTP_XOR_MULT_DOSStub_7ea7 {
  strings:
    $key_7ea7 = { 2a cf [2] 5e d7 [2] 19 d5 [2] 5e c4 [2] 10 c8 [2] 1c c2 [2] 0b c9 [2] 10 87 [2] 2d }

  condition:
    any of them
}