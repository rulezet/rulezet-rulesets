rule TTP_XOR_MULT_DOSStub_fda4 {
  strings:
    $key_fda4 = { a9 cc [2] dd d4 [2] 9a d6 [2] dd c7 [2] 93 cb [2] 9f c1 [2] 88 ca [2] 93 84 [2] ae }

  condition:
    any of them
}