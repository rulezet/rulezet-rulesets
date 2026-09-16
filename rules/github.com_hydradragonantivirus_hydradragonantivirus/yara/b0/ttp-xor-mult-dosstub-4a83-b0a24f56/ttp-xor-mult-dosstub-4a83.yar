rule TTP_XOR_MULT_DOSStub_4a83 {
  strings:
    $key_4a83 = { 1e eb [2] 6a f3 [2] 2d f1 [2] 6a e0 [2] 24 ec [2] 28 e6 [2] 3f ed [2] 24 a3 [2] 19 }

  condition:
    any of them
}