rule TTP_XOR_MULT_DOSStub_70a9 {
  strings:
    $key_70a9 = { 24 c1 [2] 50 d9 [2] 17 db [2] 50 ca [2] 1e c6 [2] 12 cc [2] 05 c7 [2] 1e 89 [2] 23 }

  condition:
    any of them
}