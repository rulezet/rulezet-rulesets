rule TTP_XOR_MULT_DOSStub_3883 {
  strings:
    $key_3883 = { 6c eb [2] 18 f3 [2] 5f f1 [2] 18 e0 [2] 56 ec [2] 5a e6 [2] 4d ed [2] 56 a3 [2] 6b }

  condition:
    any of them
}