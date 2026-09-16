rule TTP_XOR_MULT_DOSStub_7983 {
  strings:
    $key_7983 = { 2d eb [2] 59 f3 [2] 1e f1 [2] 59 e0 [2] 17 ec [2] 1b e6 [2] 0c ed [2] 17 a3 [2] 2a }

  condition:
    any of them
}