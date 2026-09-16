rule TTP_XOR_MULT_DOSStub_33a0 {
  strings:
    $key_33a0 = { 67 c8 [2] 13 d0 [2] 54 d2 [2] 13 c3 [2] 5d cf [2] 51 c5 [2] 46 ce [2] 5d 80 [2] 60 }

  condition:
    any of them
}