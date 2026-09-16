rule TTP_XOR_MULT_DOSStub_15a7 {
  strings:
    $key_15a7 = { 41 cf [2] 35 d7 [2] 72 d5 [2] 35 c4 [2] 7b c8 [2] 77 c2 [2] 60 c9 [2] 7b 87 [2] 46 }

  condition:
    any of them
}