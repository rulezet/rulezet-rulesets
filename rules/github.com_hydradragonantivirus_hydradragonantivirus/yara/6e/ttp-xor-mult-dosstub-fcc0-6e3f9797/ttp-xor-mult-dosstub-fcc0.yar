rule TTP_XOR_MULT_DOSStub_fcc0 {
  strings:
    $key_fcc0 = { a8 a8 [2] dc b0 [2] 9b b2 [2] dc a3 [2] 92 af [2] 9e a5 [2] 89 ae [2] 92 e0 [2] af }

  condition:
    any of them
}