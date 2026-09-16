rule TTP_XOR_MULT_DOSStub_3fc2 {
  strings:
    $key_3fc2 = { 6b aa [2] 1f b2 [2] 58 b0 [2] 1f a1 [2] 51 ad [2] 5d a7 [2] 4a ac [2] 51 e2 [2] 6c }

  condition:
    any of them
}