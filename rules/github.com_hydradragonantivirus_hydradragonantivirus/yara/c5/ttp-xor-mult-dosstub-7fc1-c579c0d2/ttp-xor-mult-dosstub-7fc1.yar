rule TTP_XOR_MULT_DOSStub_7fc1 {
  strings:
    $key_7fc1 = { 2b a9 [2] 5f b1 [2] 18 b3 [2] 5f a2 [2] 11 ae [2] 1d a4 [2] 0a af [2] 11 e1 [2] 2c }

  condition:
    any of them
}