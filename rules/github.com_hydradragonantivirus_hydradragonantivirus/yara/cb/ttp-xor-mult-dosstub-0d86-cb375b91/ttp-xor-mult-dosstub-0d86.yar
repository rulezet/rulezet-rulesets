rule TTP_XOR_MULT_DOSStub_0d86 {
  strings:
    $key_0d86 = { 59 ee [2] 2d f6 [2] 6a f4 [2] 2d e5 [2] 63 e9 [2] 6f e3 [2] 78 e8 [2] 63 a6 [2] 5e }

  condition:
    any of them
}