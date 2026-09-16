rule TTP_XOR_MULT_DOSStub_1fc0 {
  strings:
    $key_1fc0 = { 4b a8 [2] 3f b0 [2] 78 b2 [2] 3f a3 [2] 71 af [2] 7d a5 [2] 6a ae [2] 71 e0 [2] 4c }

  condition:
    any of them
}