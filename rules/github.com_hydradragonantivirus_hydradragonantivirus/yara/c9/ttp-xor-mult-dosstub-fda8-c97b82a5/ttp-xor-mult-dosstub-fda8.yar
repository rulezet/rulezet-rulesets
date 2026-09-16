rule TTP_XOR_MULT_DOSStub_fda8 {
  strings:
    $key_fda8 = { a9 c0 [2] dd d8 [2] 9a da [2] dd cb [2] 93 c7 [2] 9f cd [2] 88 c6 [2] 93 88 [2] ae }

  condition:
    any of them
}