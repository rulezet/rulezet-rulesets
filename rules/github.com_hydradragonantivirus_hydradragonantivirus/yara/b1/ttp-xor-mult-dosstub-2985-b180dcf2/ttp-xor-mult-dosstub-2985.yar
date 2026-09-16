rule TTP_XOR_MULT_DOSStub_2985 {
  strings:
    $key_2985 = { 7d ed [2] 09 f5 [2] 4e f7 [2] 09 e6 [2] 47 ea [2] 4b e0 [2] 5c eb [2] 47 a5 [2] 7a }

  condition:
    any of them
}