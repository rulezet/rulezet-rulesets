rule TTP_XOR_MULT_DOSStub_77a4 {
  strings:
    $key_77a4 = { 23 cc [2] 57 d4 [2] 10 d6 [2] 57 c7 [2] 19 cb [2] 15 c1 [2] 02 ca [2] 19 84 [2] 24 }

  condition:
    any of them
}