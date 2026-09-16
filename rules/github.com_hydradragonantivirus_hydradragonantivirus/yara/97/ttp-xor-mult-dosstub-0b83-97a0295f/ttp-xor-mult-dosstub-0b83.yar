rule TTP_XOR_MULT_DOSStub_0b83 {
  strings:
    $key_0b83 = { 5f eb [2] 2b f3 [2] 6c f1 [2] 2b e0 [2] 65 ec [2] 69 e6 [2] 7e ed [2] 65 a3 [2] 58 }

  condition:
    any of them
}