rule TTP_XOR_MULT_DOSStub_4a85 {
  strings:
    $key_4a85 = { 1e ed [2] 6a f5 [2] 2d f7 [2] 6a e6 [2] 24 ea [2] 28 e0 [2] 3f eb [2] 24 a5 [2] 19 }

  condition:
    any of them
}