rule TTP_XOR_MULT_DOSStub_4883 {
  strings:
    $key_4883 = { 1c eb [2] 68 f3 [2] 2f f1 [2] 68 e0 [2] 26 ec [2] 2a e6 [2] 3d ed [2] 26 a3 [2] 1b }

  condition:
    any of them
}