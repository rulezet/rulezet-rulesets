rule TTP_XOR_MULT_DOSStub_3a85 {
  strings:
    $key_3a85 = { 6e ed [2] 1a f5 [2] 5d f7 [2] 1a e6 [2] 54 ea [2] 58 e0 [2] 4f eb [2] 54 a5 [2] 69 }

  condition:
    any of them
}