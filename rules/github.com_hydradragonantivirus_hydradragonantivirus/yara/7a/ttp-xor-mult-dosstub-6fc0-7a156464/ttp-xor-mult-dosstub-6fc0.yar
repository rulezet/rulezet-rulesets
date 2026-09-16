rule TTP_XOR_MULT_DOSStub_6fc0 {
  strings:
    $key_6fc0 = { 3b a8 [2] 4f b0 [2] 08 b2 [2] 4f a3 [2] 01 af [2] 0d a5 [2] 1a ae [2] 01 e0 [2] 3c }

  condition:
    any of them
}