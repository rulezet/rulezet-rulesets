rule TTP_XOR_MULT_DOSStub_fcc2 {
  strings:
    $key_fcc2 = { a8 aa [2] dc b2 [2] 9b b0 [2] dc a1 [2] 92 ad [2] 9e a7 [2] 89 ac [2] 92 e2 [2] af }

  condition:
    any of them
}