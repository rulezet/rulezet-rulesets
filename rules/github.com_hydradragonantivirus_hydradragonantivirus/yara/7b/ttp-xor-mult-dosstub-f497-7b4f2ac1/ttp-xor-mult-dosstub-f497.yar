rule TTP_XOR_MULT_DOSStub_f497 {
  strings:
    $key_f497 = { a0 ff [2] d4 e7 [2] 93 e5 [2] d4 f4 [2] 9a f8 [2] 96 f2 [2] 81 f9 [2] 9a b7 [2] a7 }

  condition:
    any of them
}