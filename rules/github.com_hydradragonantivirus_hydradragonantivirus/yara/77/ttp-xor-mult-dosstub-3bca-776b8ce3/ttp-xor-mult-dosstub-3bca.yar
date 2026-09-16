rule TTP_XOR_MULT_DOSStub_3bca {
  strings:
    $key_3bca = { 6f a2 [2] 1b ba [2] 5c b8 [2] 1b a9 [2] 55 a5 [2] 59 af [2] 4e a4 [2] 55 ea [2] 68 }

  condition:
    any of them
}