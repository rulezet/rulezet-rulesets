rule TTP_XOR_MULT_DOSStub_2fc0 {
  strings:
    $key_2fc0 = { 7b a8 [2] 0f b0 [2] 48 b2 [2] 0f a3 [2] 41 af [2] 4d a5 [2] 5a ae [2] 41 e0 [2] 7c }

  condition:
    any of them
}