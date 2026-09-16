rule TTP_XOR_MULT_DOSStub_7e85 {
  strings:
    $key_7e85 = { 2a ed [2] 5e f5 [2] 19 f7 [2] 5e e6 [2] 10 ea [2] 1c e0 [2] 0b eb [2] 10 a5 [2] 2d }

  condition:
    any of them
}