rule TTP_XOR_MULT_DOSStub_7bc6 {
  strings:
    $key_7bc6 = { 2f ae [2] 5b b6 [2] 1c b4 [2] 5b a5 [2] 15 a9 [2] 19 a3 [2] 0e a8 [2] 15 e6 [2] 28 }

  condition:
    any of them
}