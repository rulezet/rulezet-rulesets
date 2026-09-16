rule TTP_XOR_MULT_DOSStub_0fc4 {
  strings:
    $key_0fc4 = { 5b ac [2] 2f b4 [2] 68 b6 [2] 2f a7 [2] 61 ab [2] 6d a1 [2] 7a aa [2] 61 e4 [2] 5c }

  condition:
    any of them
}