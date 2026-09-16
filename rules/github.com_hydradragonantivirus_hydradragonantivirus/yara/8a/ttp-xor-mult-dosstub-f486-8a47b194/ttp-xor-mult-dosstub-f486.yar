rule TTP_XOR_MULT_DOSStub_f486 {
  strings:
    $key_f486 = { a0 ee [2] d4 f6 [2] 93 f4 [2] d4 e5 [2] 9a e9 [2] 96 e3 [2] 81 e8 [2] 9a a6 [2] a7 }

  condition:
    any of them
}