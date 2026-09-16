rule TTP_XOR_MULT_DOSStub_fcd2 {
  strings:
    $key_fcd2 = { a8 ba [2] dc a2 [2] 9b a0 [2] dc b1 [2] 92 bd [2] 9e b7 [2] 89 bc [2] 92 f2 [2] af }

  condition:
    any of them
}