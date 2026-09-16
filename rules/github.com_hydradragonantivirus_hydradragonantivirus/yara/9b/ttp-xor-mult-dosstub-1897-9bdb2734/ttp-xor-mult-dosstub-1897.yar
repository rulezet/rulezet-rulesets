rule TTP_XOR_MULT_DOSStub_1897 {
  strings:
    $key_1897 = { 4c ff [2] 38 e7 [2] 7f e5 [2] 38 f4 [2] 76 f8 [2] 7a f2 [2] 6d f9 [2] 76 b7 [2] 4b }

  condition:
    any of them
}