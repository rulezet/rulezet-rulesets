rule TTP_XOR_MULT_DOSStub_6a86 {
  strings:
    $key_6a86 = { 3e ee [2] 4a f6 [2] 0d f4 [2] 4a e5 [2] 04 e9 [2] 08 e3 [2] 1f e8 [2] 04 a6 [2] 39 }

  condition:
    any of them
}