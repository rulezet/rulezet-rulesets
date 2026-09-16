rule TTP_XOR_MULT_DOSStub_1b83 {
  strings:
    $key_1b83 = { 4f eb [2] 3b f3 [2] 7c f1 [2] 3b e0 [2] 75 ec [2] 79 e6 [2] 6e ed [2] 75 a3 [2] 48 }

  condition:
    any of them
}