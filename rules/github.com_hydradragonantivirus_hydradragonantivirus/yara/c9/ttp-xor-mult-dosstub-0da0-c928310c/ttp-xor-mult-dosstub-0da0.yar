rule TTP_XOR_MULT_DOSStub_0da0 {
  strings:
    $key_0da0 = { 59 c8 [2] 2d d0 [2] 6a d2 [2] 2d c3 [2] 63 cf [2] 6f c5 [2] 78 ce [2] 63 80 [2] 5e }

  condition:
    any of them
}