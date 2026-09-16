rule TTP_XOR_MULT_DOSStub_faa1 {
  strings:
    $key_faa1 = { ae c9 [2] da d1 [2] 9d d3 [2] da c2 [2] 94 ce [2] 98 c4 [2] 8f cf [2] 94 81 [2] a9 }

  condition:
    any of them
}