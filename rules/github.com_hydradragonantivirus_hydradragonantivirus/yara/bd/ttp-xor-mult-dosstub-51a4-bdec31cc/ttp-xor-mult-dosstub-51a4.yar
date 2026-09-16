rule TTP_XOR_MULT_DOSStub_51a4 {
  strings:
    $key_51a4 = { 05 cc [2] 71 d4 [2] 36 d6 [2] 71 c7 [2] 3f cb [2] 33 c1 [2] 24 ca [2] 3f 84 [2] 02 }

  condition:
    any of them
}