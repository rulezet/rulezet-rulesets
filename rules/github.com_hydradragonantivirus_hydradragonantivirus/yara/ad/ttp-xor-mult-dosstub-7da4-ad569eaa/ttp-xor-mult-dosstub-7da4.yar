rule TTP_XOR_MULT_DOSStub_7da4 {
  strings:
    $key_7da4 = { 29 cc [2] 5d d4 [2] 1a d6 [2] 5d c7 [2] 13 cb [2] 1f c1 [2] 08 ca [2] 13 84 [2] 2e }

  condition:
    any of them
}