rule TTP_XOR_MULT_DOSStub_2e85 {
  strings:
    $key_2e85 = { 7a ed [2] 0e f5 [2] 49 f7 [2] 0e e6 [2] 40 ea [2] 4c e0 [2] 5b eb [2] 40 a5 [2] 7d }

  condition:
    any of them
}