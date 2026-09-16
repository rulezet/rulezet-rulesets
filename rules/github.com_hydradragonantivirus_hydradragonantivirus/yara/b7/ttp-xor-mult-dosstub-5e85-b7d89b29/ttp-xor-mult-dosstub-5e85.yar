rule TTP_XOR_MULT_DOSStub_5e85 {
  strings:
    $key_5e85 = { 0a ed [2] 7e f5 [2] 39 f7 [2] 7e e6 [2] 30 ea [2] 3c e0 [2] 2b eb [2] 30 a5 [2] 0d }

  condition:
    any of them
}