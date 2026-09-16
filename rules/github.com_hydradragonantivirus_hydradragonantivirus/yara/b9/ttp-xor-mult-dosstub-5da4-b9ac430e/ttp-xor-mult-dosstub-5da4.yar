rule TTP_XOR_MULT_DOSStub_5da4 {
  strings:
    $key_5da4 = { 09 cc [2] 7d d4 [2] 3a d6 [2] 7d c7 [2] 33 cb [2] 3f c1 [2] 28 ca [2] 33 84 [2] 0e }

  condition:
    any of them
}