rule TTP_XOR_MULT_DOSStub_3b83 {
  strings:
    $key_3b83 = { 6f eb [2] 1b f3 [2] 5c f1 [2] 1b e0 [2] 55 ec [2] 59 e6 [2] 4e ed [2] 55 a3 [2] 68 }

  condition:
    any of them
}