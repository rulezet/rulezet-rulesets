rule TTP_XOR_MULT_DOSStub_8187 {
  strings:
    $key_8187 = { d5 ef [2] a1 f7 [2] e6 f5 [2] a1 e4 [2] ef e8 [2] e3 e2 [2] f4 e9 [2] ef a7 [2] d2 }

  condition:
    any of them
}