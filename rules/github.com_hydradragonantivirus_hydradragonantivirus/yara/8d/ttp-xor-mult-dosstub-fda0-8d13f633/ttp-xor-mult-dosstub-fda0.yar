rule TTP_XOR_MULT_DOSStub_fda0 {
  strings:
    $key_fda0 = { a9 c8 [2] dd d0 [2] 9a d2 [2] dd c3 [2] 93 cf [2] 9f c5 [2] 88 ce [2] 93 80 [2] ae }

  condition:
    any of them
}