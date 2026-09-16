rule TTP_XOR_MULT_DOSStub_46a4 {
  strings:
    $key_46a4 = { 12 cc [2] 66 d4 [2] 21 d6 [2] 66 c7 [2] 28 cb [2] 24 c1 [2] 33 ca [2] 28 84 [2] 15 }

  condition:
    any of them
}