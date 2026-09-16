rule TTP_XOR_MULT_DOSStub_0883 {
  strings:
    $key_0883 = { 5c eb [2] 28 f3 [2] 6f f1 [2] 28 e0 [2] 66 ec [2] 6a e6 [2] 7d ed [2] 66 a3 [2] 5b }

  condition:
    any of them
}