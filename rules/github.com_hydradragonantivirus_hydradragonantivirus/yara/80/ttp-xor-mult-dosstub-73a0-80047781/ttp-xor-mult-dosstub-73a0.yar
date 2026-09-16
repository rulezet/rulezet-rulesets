rule TTP_XOR_MULT_DOSStub_73a0 {
  strings:
    $key_73a0 = { 27 c8 [2] 53 d0 [2] 14 d2 [2] 53 c3 [2] 1d cf [2] 11 c5 [2] 06 ce [2] 1d 80 [2] 20 }

  condition:
    any of them
}