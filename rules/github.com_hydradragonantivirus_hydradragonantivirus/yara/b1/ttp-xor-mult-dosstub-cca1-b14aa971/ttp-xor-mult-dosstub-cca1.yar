rule TTP_XOR_MULT_DOSStub_cca1 {
  strings:
    $key_cca1 = { 98 c9 [2] ec d1 [2] ab d3 [2] ec c2 [2] a2 ce [2] ae c4 [2] b9 cf [2] a2 81 [2] 9f }

  condition:
    any of them
}