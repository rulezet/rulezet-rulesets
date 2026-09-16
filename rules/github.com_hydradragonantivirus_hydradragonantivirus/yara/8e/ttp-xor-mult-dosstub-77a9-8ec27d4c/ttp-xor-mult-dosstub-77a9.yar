rule TTP_XOR_MULT_DOSStub_77a9 {
  strings:
    $key_77a9 = { 23 c1 [2] 57 d9 [2] 10 db [2] 57 ca [2] 19 c6 [2] 15 cc [2] 02 c7 [2] 19 89 [2] 24 }

  condition:
    any of them
}