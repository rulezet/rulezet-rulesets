rule TTP_XOR_MULT_DOSStub_0897 {
  strings:
    $key_0897 = { 5c ff [2] 28 e7 [2] 6f e5 [2] 28 f4 [2] 66 f8 [2] 6a f2 [2] 7d f9 [2] 66 b7 [2] 5b }

  condition:
    any of them
}