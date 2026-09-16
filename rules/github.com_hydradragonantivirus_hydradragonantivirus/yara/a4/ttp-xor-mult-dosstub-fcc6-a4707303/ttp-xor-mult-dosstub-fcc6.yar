rule TTP_XOR_MULT_DOSStub_fcc6 {
  strings:
    $key_fcc6 = { a8 ae [2] dc b6 [2] 9b b4 [2] dc a5 [2] 92 a9 [2] 9e a3 [2] 89 a8 [2] 92 e6 [2] af }

  condition:
    any of them
}