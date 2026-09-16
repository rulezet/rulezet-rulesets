rule TTP_XOR_MULT_DOSStub_4d85 {
  strings:
    $key_4d85 = { 19 ed [2] 6d f5 [2] 2a f7 [2] 6d e6 [2] 23 ea [2] 2f e0 [2] 38 eb [2] 23 a5 [2] 1e }

  condition:
    any of them
}