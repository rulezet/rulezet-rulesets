rule TTP_XOR_MULT_DOSStub_fa96 {
  strings:
    $key_fa96 = { ae fe [2] da e6 [2] 9d e4 [2] da f5 [2] 94 f9 [2] 98 f3 [2] 8f f8 [2] 94 b6 [2] a9 }

  condition:
    any of them
}