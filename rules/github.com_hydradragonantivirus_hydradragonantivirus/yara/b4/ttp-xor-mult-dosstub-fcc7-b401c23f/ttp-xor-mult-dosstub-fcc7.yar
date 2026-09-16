rule TTP_XOR_MULT_DOSStub_fcc7 {
  strings:
    $key_fcc7 = { a8 af [2] dc b7 [2] 9b b5 [2] dc a4 [2] 92 a8 [2] 9e a2 [2] 89 a9 [2] 92 e7 [2] af }

  condition:
    any of them
}