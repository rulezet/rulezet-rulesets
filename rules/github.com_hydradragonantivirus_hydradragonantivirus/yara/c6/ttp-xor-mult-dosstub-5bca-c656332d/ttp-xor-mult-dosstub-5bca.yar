rule TTP_XOR_MULT_DOSStub_5bca {
  strings:
    $key_5bca = { 0f a2 [2] 7b ba [2] 3c b8 [2] 7b a9 [2] 35 a5 [2] 39 af [2] 2e a4 [2] 35 ea [2] 08 }

  condition:
    any of them
}