rule TTP_XOR_MULT_DOSStub_fcd5 {
  strings:
    $key_fcd5 = { a8 bd [2] dc a5 [2] 9b a7 [2] dc b6 [2] 92 ba [2] 9e b0 [2] 89 bb [2] 92 f5 [2] af }

  condition:
    any of them
}