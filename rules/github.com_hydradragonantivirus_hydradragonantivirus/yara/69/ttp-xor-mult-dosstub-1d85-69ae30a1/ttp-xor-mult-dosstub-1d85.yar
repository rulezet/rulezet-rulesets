rule TTP_XOR_MULT_DOSStub_1d85 {
  strings:
    $key_1d85 = { 49 ed [2] 3d f5 [2] 7a f7 [2] 3d e6 [2] 73 ea [2] 7f e0 [2] 68 eb [2] 73 a5 [2] 4e }

  condition:
    any of them
}