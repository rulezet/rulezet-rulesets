rule TTP_XOR_MULT_DOSStub_1da0 {
  strings:
    $key_1da0 = { 49 c8 [2] 3d d0 [2] 7a d2 [2] 3d c3 [2] 73 cf [2] 7f c5 [2] 68 ce [2] 73 80 [2] 4e }

  condition:
    any of them
}