rule TTP_XOR_MULT_DOSStub_2ba7 {
  strings:
    $key_2ba7 = { 7f cf [2] 0b d7 [2] 4c d5 [2] 0b c4 [2] 45 c8 [2] 49 c2 [2] 5e c9 [2] 45 87 [2] 78 }

  condition:
    any of them
}