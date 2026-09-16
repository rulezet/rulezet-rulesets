rule TTP_XOR_MULT_DOSStub_f496 {
  strings:
    $key_f496 = { a0 fe [2] d4 e6 [2] 93 e4 [2] d4 f5 [2] 9a f9 [2] 96 f3 [2] 81 f8 [2] 9a b6 [2] a7 }

  condition:
    any of them
}