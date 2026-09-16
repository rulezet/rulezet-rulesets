rule TTP_XOR_MULT_DOSStub_0e85 {
  strings:
    $key_0e85 = { 5a ed [2] 2e f5 [2] 69 f7 [2] 2e e6 [2] 60 ea [2] 6c e0 [2] 7b eb [2] 60 a5 [2] 5d }

  condition:
    any of them
}