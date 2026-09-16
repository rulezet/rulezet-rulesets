rule TTP_XOR_MULT_DOSStub_0ed6 {
  strings:
    $key_0ed6 = { 5a be [2] 2e a6 [2] 69 a4 [2] 2e b5 [2] 60 b9 [2] 6c b3 [2] 7b b8 [2] 60 f6 [2] 5d }

  condition:
    any of them
}