rule TTP_XOR_MULT_DOSStub_51a0 {
  strings:
    $key_51a0 = { 05 c8 [2] 71 d0 [2] 36 d2 [2] 71 c3 [2] 3f cf [2] 33 c5 [2] 24 ce [2] 3f 80 [2] 02 }

  condition:
    any of them
}