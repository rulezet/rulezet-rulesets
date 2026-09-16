rule TTP_XOR_MULT_DOSStub_42a4 {
  strings:
    $key_42a4 = { 16 cc [2] 62 d4 [2] 25 d6 [2] 62 c7 [2] 2c cb [2] 20 c1 [2] 37 ca [2] 2c 84 [2] 11 }

  condition:
    any of them
}