rule TTP_XOR_MULT_DOSStub_3da4 {
  strings:
    $key_3da4 = { 69 cc [2] 1d d4 [2] 5a d6 [2] 1d c7 [2] 53 cb [2] 5f c1 [2] 48 ca [2] 53 84 [2] 6e }

  condition:
    any of them
}