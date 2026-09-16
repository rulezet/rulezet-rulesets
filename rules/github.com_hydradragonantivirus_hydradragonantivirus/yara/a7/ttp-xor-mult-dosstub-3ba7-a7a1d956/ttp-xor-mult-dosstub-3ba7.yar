rule TTP_XOR_MULT_DOSStub_3ba7 {
  strings:
    $key_3ba7 = { 6f cf [2] 1b d7 [2] 5c d5 [2] 1b c4 [2] 55 c8 [2] 59 c2 [2] 4e c9 [2] 55 87 [2] 68 }

  condition:
    any of them
}