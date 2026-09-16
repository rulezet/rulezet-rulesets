rule TTP_XOR_MULT_DOSStub_56a7 {
  strings:
    $key_56a7 = { 02 cf [2] 76 d7 [2] 31 d5 [2] 76 c4 [2] 38 c8 [2] 34 c2 [2] 23 c9 [2] 38 87 [2] 05 }

  condition:
    any of them
}