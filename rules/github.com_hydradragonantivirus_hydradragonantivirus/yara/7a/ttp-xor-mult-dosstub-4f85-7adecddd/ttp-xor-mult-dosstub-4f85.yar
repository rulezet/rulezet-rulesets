rule TTP_XOR_MULT_DOSStub_4f85 {
  strings:
    $key_4f85 = { 1b ed [2] 6f f5 [2] 28 f7 [2] 6f e6 [2] 21 ea [2] 2d e0 [2] 3a eb [2] 21 a5 [2] 1c }

  condition:
    any of them
}