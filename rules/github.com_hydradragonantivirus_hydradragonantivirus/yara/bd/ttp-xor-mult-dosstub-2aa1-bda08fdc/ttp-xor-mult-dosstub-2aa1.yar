rule TTP_XOR_MULT_DOSStub_2aa1 {
  strings:
    $key_2aa1 = { 7e c9 [2] 0a d1 [2] 4d d3 [2] 0a c2 [2] 44 ce [2] 48 c4 [2] 5f cf [2] 44 81 [2] 79 }

  condition:
    any of them
}