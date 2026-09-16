rule TTP_XOR_MULT_DOSStub_6f85 {
  strings:
    $key_6f85 = { 3b ed [2] 4f f5 [2] 08 f7 [2] 4f e6 [2] 01 ea [2] 0d e0 [2] 1a eb [2] 01 a5 [2] 3c }

  condition:
    any of them
}