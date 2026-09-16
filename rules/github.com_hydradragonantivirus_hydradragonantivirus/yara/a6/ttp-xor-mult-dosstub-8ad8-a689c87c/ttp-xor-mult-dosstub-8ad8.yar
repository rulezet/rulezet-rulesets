rule TTP_XOR_MULT_DOSStub_8ad8 {
  strings:
    $key_8ad8 = { de b0 [2] aa a8 [2] ed aa [2] aa bb [2] e4 b7 [2] e8 bd [2] ff b6 [2] e4 f8 [2] d9 }

  condition:
    any of them
}