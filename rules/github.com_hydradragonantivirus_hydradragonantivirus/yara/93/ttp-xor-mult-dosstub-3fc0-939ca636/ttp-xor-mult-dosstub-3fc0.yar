rule TTP_XOR_MULT_DOSStub_3fc0 {
  strings:
    $key_3fc0 = { 6b a8 [2] 1f b0 [2] 58 b2 [2] 1f a3 [2] 51 af [2] 5d a5 [2] 4a ae [2] 51 e0 [2] 6c }

  condition:
    any of them
}