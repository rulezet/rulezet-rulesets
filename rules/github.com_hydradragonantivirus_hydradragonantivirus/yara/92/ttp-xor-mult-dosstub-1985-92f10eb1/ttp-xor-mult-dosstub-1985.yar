rule TTP_XOR_MULT_DOSStub_1985 {
  strings:
    $key_1985 = { 4d ed [2] 39 f5 [2] 7e f7 [2] 39 e6 [2] 77 ea [2] 7b e0 [2] 6c eb [2] 77 a5 [2] 4a }

  condition:
    any of them
}