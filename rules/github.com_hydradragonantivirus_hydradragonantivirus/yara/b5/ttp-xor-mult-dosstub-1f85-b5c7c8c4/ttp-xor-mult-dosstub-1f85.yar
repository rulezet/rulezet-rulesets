rule TTP_XOR_MULT_DOSStub_1f85 {
  strings:
    $key_1f85 = { 4b ed [2] 3f f5 [2] 78 f7 [2] 3f e6 [2] 71 ea [2] 7d e0 [2] 6a eb [2] 71 a5 [2] 4c }

  condition:
    any of them
}