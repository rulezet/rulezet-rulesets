rule TTP_XOR_MULT_DOSStub_4b85 {
  strings:
    $key_4b85 = { 1f ed [2] 6b f5 [2] 2c f7 [2] 6b e6 [2] 25 ea [2] 29 e0 [2] 3e eb [2] 25 a5 [2] 18 }

  condition:
    any of them
}