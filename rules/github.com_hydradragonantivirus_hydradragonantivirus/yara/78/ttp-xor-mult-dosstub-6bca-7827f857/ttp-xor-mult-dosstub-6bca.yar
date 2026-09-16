rule TTP_XOR_MULT_DOSStub_6bca {
  strings:
    $key_6bca = { 3f a2 [2] 4b ba [2] 0c b8 [2] 4b a9 [2] 05 a5 [2] 09 af [2] 1e a4 [2] 05 ea [2] 38 }

  condition:
    any of them
}