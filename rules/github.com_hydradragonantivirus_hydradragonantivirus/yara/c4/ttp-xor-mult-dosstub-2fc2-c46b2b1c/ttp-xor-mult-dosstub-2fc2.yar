rule TTP_XOR_MULT_DOSStub_2fc2 {
  strings:
    $key_2fc2 = { 7b aa [2] 0f b2 [2] 48 b0 [2] 0f a1 [2] 41 ad [2] 4d a7 [2] 5a ac [2] 41 e2 [2] 7c }

  condition:
    any of them
}