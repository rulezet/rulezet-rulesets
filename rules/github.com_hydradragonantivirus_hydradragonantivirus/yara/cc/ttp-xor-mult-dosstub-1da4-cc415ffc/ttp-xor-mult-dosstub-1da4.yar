rule TTP_XOR_MULT_DOSStub_1da4 {
  strings:
    $key_1da4 = { 49 cc [2] 3d d4 [2] 7a d6 [2] 3d c7 [2] 73 cb [2] 7f c1 [2] 68 ca [2] 73 84 [2] 4e }

  condition:
    any of them
}