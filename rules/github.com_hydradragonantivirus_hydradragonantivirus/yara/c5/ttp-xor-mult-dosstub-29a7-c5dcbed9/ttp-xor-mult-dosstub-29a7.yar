rule TTP_XOR_MULT_DOSStub_29a7 {
  strings:
    $key_29a7 = { 7d cf [2] 09 d7 [2] 4e d5 [2] 09 c4 [2] 47 c8 [2] 4b c2 [2] 5c c9 [2] 47 87 [2] 7a }

  condition:
    any of them
}