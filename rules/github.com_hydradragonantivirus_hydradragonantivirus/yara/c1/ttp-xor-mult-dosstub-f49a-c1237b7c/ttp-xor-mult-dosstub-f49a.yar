rule TTP_XOR_MULT_DOSStub_f49a {
  strings:
    $key_f49a = { a0 f2 [2] d4 ea [2] 93 e8 [2] d4 f9 [2] 9a f5 [2] 96 ff [2] 81 f4 [2] 9a ba [2] a7 }

  condition:
    any of them
}