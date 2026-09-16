rule TTP_XOR_MULT_DOSStub_1a85 {
  strings:
    $key_1a85 = { 4e ed [2] 3a f5 [2] 7d f7 [2] 3a e6 [2] 74 ea [2] 78 e0 [2] 6f eb [2] 74 a5 [2] 49 }

  condition:
    any of them
}