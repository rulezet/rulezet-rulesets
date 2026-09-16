rule TTP_XOR_MULT_DOSStub_6da0 {
  strings:
    $key_6da0 = { 39 c8 [2] 4d d0 [2] 0a d2 [2] 4d c3 [2] 03 cf [2] 0f c5 [2] 18 ce [2] 03 80 [2] 3e }

  condition:
    any of them
}