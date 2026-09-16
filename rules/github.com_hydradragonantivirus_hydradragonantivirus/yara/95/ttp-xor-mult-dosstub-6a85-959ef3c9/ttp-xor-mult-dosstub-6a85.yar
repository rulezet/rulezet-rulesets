rule TTP_XOR_MULT_DOSStub_6a85 {
  strings:
    $key_6a85 = { 3e ed [2] 4a f5 [2] 0d f7 [2] 4a e6 [2] 04 ea [2] 08 e0 [2] 1f eb [2] 04 a5 [2] 39 }

  condition:
    any of them
}