rule TTP_XOR_MULT_DOSStub_07a4 {
  strings:
    $key_07a4 = { 53 cc [2] 27 d4 [2] 60 d6 [2] 27 c7 [2] 69 cb [2] 65 c1 [2] 72 ca [2] 69 84 [2] 54 }

  condition:
    any of them
}