rule TTP_XOR_MULT_DOSStub_4fc1 {
  strings:
    $key_4fc1 = { 1b a9 [2] 6f b1 [2] 28 b3 [2] 6f a2 [2] 21 ae [2] 2d a4 [2] 3a af [2] 21 e1 [2] 1c }

  condition:
    any of them
}