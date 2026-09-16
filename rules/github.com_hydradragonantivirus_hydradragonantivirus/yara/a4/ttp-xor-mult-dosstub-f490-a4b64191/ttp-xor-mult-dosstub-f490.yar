rule TTP_XOR_MULT_DOSStub_f490 {
  strings:
    $key_f490 = { a0 f8 [2] d4 e0 [2] 93 e2 [2] d4 f3 [2] 9a ff [2] 96 f5 [2] 81 fe [2] 9a b0 [2] a7 }

  condition:
    any of them
}