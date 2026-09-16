rule TTP_XOR_MULT_DOSStub_3da0 {
  strings:
    $key_3da0 = { 69 c8 [2] 1d d0 [2] 5a d2 [2] 1d c3 [2] 53 cf [2] 5f c5 [2] 48 ce [2] 53 80 [2] 6e }

  condition:
    any of them
}