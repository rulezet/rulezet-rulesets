rule TTP_XOR_MULT_DOSStub_fdd6 {
  strings:
    $key_fdd6 = { a9 be [2] dd a6 [2] 9a a4 [2] dd b5 [2] 93 b9 [2] 9f b3 [2] 88 b8 [2] 93 f6 [2] ae }

  condition:
    any of them
}