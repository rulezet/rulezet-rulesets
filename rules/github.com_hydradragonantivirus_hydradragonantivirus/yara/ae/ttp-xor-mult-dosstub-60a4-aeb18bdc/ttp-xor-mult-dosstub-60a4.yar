rule TTP_XOR_MULT_DOSStub_60a4 {
  strings:
    $key_60a4 = { 34 cc [2] 40 d4 [2] 07 d6 [2] 40 c7 [2] 0e cb [2] 02 c1 [2] 15 ca [2] 0e 84 [2] 33 }

  condition:
    any of them
}