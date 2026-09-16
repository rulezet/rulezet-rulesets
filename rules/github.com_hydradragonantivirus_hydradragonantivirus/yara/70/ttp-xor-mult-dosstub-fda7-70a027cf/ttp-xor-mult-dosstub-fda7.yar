rule TTP_XOR_MULT_DOSStub_fda7 {
  strings:
    $key_fda7 = { a9 cf [2] dd d7 [2] 9a d5 [2] dd c4 [2] 93 c8 [2] 9f c2 [2] 88 c9 [2] 93 87 [2] ae }

  condition:
    any of them
}