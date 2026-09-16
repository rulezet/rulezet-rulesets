rule TTP_XOR_MULT_DOSStub_0bca {
  strings:
    $key_0bca = { 5f a2 [2] 2b ba [2] 6c b8 [2] 2b a9 [2] 65 a5 [2] 69 af [2] 7e a4 [2] 65 ea [2] 58 }

  condition:
    any of them
}