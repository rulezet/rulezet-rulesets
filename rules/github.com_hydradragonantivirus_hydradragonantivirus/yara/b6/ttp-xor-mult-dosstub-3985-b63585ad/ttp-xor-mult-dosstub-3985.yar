rule TTP_XOR_MULT_DOSStub_3985 {
  strings:
    $key_3985 = { 6d ed [2] 19 f5 [2] 5e f7 [2] 19 e6 [2] 57 ea [2] 5b e0 [2] 4c eb [2] 57 a5 [2] 6a }

  condition:
    any of them
}