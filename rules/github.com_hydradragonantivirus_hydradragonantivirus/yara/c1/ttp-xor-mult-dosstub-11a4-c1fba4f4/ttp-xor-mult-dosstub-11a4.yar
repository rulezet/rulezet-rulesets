rule TTP_XOR_MULT_DOSStub_11a4 {
  strings:
    $key_11a4 = { 45 cc [2] 31 d4 [2] 76 d6 [2] 31 c7 [2] 7f cb [2] 73 c1 [2] 64 ca [2] 7f 84 [2] 42 }

  condition:
    any of them
}