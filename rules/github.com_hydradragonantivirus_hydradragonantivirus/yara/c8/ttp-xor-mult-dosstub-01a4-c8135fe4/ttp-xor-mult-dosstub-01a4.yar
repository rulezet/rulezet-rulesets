rule TTP_XOR_MULT_DOSStub_01a4 {
  strings:
    $key_01a4 = { 55 cc [2] 21 d4 [2] 66 d6 [2] 21 c7 [2] 6f cb [2] 63 c1 [2] 74 ca [2] 6f 84 [2] 52 }

  condition:
    any of them
}