rule TTP_XOR_MULT_DOSStub_0fc7 {
  strings:
    $key_0fc7 = { 5b af [2] 2f b7 [2] 68 b5 [2] 2f a4 [2] 61 a8 [2] 6d a2 [2] 7a a9 [2] 61 e7 [2] 5c }

  condition:
    any of them
}