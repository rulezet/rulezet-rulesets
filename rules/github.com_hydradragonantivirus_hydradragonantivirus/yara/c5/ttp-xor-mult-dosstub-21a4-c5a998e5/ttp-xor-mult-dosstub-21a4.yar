rule TTP_XOR_MULT_DOSStub_21a4 {
  strings:
    $key_21a4 = { 75 cc [2] 01 d4 [2] 46 d6 [2] 01 c7 [2] 4f cb [2] 43 c1 [2] 54 ca [2] 4f 84 [2] 72 }

  condition:
    any of them
}