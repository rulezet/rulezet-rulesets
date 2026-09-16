rule TTP_XOR_MULT_DOSStub_4e85 {
  strings:
    $key_4e85 = { 1a ed [2] 6e f5 [2] 29 f7 [2] 6e e6 [2] 20 ea [2] 2c e0 [2] 3b eb [2] 20 a5 [2] 1d }

  condition:
    any of them
}