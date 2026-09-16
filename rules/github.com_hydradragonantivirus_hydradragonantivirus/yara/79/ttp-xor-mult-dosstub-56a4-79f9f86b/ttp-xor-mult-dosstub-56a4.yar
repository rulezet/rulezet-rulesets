rule TTP_XOR_MULT_DOSStub_56a4 {
  strings:
    $key_56a4 = { 02 cc [2] 76 d4 [2] 31 d6 [2] 76 c7 [2] 38 cb [2] 34 c1 [2] 23 ca [2] 38 84 [2] 05 }

  condition:
    any of them
}