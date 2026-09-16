rule TTP_XOR_MULT_DOSStub_09a7 {
  strings:
    $key_09a7 = { 5d cf [2] 29 d7 [2] 6e d5 [2] 29 c4 [2] 67 c8 [2] 6b c2 [2] 7c c9 [2] 67 87 [2] 5a }

  condition:
    any of them
}