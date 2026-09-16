rule TTP_XOR_MULT_DOSStub_6d87 {
  strings:
    $key_6d87 = { 39 ef [2] 4d f7 [2] 0a f5 [2] 4d e4 [2] 03 e8 [2] 0f e2 [2] 18 e9 [2] 03 a7 [2] 3e }

  condition:
    any of them
}