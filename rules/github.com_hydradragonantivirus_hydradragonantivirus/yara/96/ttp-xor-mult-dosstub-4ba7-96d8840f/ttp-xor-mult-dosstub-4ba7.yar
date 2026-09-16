rule TTP_XOR_MULT_DOSStub_4ba7 {
  strings:
    $key_4ba7 = { 1f cf [2] 6b d7 [2] 2c d5 [2] 6b c4 [2] 25 c8 [2] 29 c2 [2] 3e c9 [2] 25 87 [2] 18 }

  condition:
    any of them
}