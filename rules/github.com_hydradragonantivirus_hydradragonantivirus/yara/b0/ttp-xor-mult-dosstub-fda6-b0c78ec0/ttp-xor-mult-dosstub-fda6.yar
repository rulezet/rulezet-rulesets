rule TTP_XOR_MULT_DOSStub_fda6 {
  strings:
    $key_fda6 = { a9 ce [2] dd d6 [2] 9a d4 [2] dd c5 [2] 93 c9 [2] 9f c3 [2] 88 c8 [2] 93 86 [2] ae }

  condition:
    any of them
}