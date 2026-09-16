rule TTP_XOR_MULT_DOSStub_fcc9 {
  strings:
    $key_fcc9 = { a8 a1 [2] dc b9 [2] 9b bb [2] dc aa [2] 92 a6 [2] 9e ac [2] 89 a7 [2] 92 e9 [2] af }

  condition:
    any of them
}