rule TTP_XOR_MULT_DOSStub_0fc1 {
  strings:
    $key_0fc1 = { 5b a9 [2] 2f b1 [2] 68 b3 [2] 2f a2 [2] 61 ae [2] 6d a4 [2] 7a af [2] 61 e1 [2] 5c }

  condition:
    any of them
}