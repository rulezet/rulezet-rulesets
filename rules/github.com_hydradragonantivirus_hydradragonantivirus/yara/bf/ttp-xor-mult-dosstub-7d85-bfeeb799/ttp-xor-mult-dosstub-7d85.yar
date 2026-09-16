rule TTP_XOR_MULT_DOSStub_7d85 {
  strings:
    $key_7d85 = { 29 ed [2] 5d f5 [2] 1a f7 [2] 5d e6 [2] 13 ea [2] 1f e0 [2] 08 eb [2] 13 a5 [2] 2e }

  condition:
    any of them
}