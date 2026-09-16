rule TTP_XOR_MULT_DOSStub_56a9 {
  strings:
    $key_56a9 = { 02 c1 [2] 76 d9 [2] 31 db [2] 76 ca [2] 38 c6 [2] 34 cc [2] 23 c7 [2] 38 89 [2] 05 }

  condition:
    any of them
}