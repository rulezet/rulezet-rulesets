rule TTP_XOR_MULT_DOSStub_1ba1 {
  strings:
    $key_1ba1 = { 4f c9 [2] 3b d1 [2] 7c d3 [2] 3b c2 [2] 75 ce [2] 79 c4 [2] 6e cf [2] 75 81 [2] 48 }

  condition:
    any of them
}