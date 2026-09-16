rule TTP_XOR_MULT_DOSStub_fcc4 {
  strings:
    $key_fcc4 = { a8 ac [2] dc b4 [2] 9b b6 [2] dc a7 [2] 92 ab [2] 9e a1 [2] 89 aa [2] 92 e4 [2] af }

  condition:
    any of them
}