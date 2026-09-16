rule TTP_XOR_MULT_DOSStub_7bca {
  strings:
    $key_7bca = { 2f a2 [2] 5b ba [2] 1c b8 [2] 5b a9 [2] 15 a5 [2] 19 af [2] 0e a4 [2] 15 ea [2] 28 }

  condition:
    any of them
}