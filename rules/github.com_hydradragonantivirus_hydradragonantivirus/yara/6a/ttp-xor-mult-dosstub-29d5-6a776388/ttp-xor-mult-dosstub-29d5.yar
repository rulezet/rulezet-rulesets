rule TTP_XOR_MULT_DOSStub_29d5 {
  strings:
    $key_29d5 = { 7d bd [2] 09 a5 [2] 4e a7 [2] 09 b6 [2] 47 ba [2] 4b b0 [2] 5c bb [2] 47 f5 [2] 7a }

  condition:
    any of them
}