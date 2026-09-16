rule TTP_XOR_MULT_DOSStub_50a4 {
  strings:
    $key_50a4 = { 04 cc [2] 70 d4 [2] 37 d6 [2] 70 c7 [2] 3e cb [2] 32 c1 [2] 25 ca [2] 3e 84 [2] 03 }

  condition:
    any of them
}