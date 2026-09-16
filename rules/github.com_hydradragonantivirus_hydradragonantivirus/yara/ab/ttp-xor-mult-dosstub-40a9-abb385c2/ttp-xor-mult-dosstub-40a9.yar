rule TTP_XOR_MULT_DOSStub_40a9 {
  strings:
    $key_40a9 = { 14 c1 [2] 60 d9 [2] 27 db [2] 60 ca [2] 2e c6 [2] 22 cc [2] 35 c7 [2] 2e 89 [2] 13 }

  condition:
    any of them
}