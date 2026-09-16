rule TTP_XOR_MULT_DOSStub_0d85 {
  strings:
    $key_0d85 = { 59 ed [2] 2d f5 [2] 6a f7 [2] 2d e6 [2] 63 ea [2] 6f e0 [2] 78 eb [2] 63 a5 [2] 5e }

  condition:
    any of them
}