rule TTP_XOR_MULT_DOSStub_0985 {
  strings:
    $key_0985 = { 5d ed [2] 29 f5 [2] 6e f7 [2] 29 e6 [2] 67 ea [2] 6b e0 [2] 7c eb [2] 67 a5 [2] 5a }

  condition:
    any of them
}