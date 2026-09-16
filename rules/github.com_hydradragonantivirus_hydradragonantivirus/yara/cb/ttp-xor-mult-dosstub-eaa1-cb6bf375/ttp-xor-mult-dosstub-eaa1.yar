rule TTP_XOR_MULT_DOSStub_eaa1 {
  strings:
    $key_eaa1 = { be c9 [2] ca d1 [2] 8d d3 [2] ca c2 [2] 84 ce [2] 88 c4 [2] 9f cf [2] 84 81 [2] b9 }

  condition:
    any of them
}