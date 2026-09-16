rule TTP_XOR_MULT_DOSStub_2897 {
  strings:
    $key_2897 = { 7c ff [2] 08 e7 [2] 4f e5 [2] 08 f4 [2] 46 f8 [2] 4a f2 [2] 5d f9 [2] 46 b7 [2] 7b }

  condition:
    any of them
}