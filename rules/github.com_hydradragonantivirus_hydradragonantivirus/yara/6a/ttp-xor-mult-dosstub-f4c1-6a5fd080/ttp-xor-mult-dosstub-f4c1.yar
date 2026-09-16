rule TTP_XOR_MULT_DOSStub_f4c1 {
  strings:
    $key_f4c1 = { a0 a9 [2] d4 b1 [2] 93 b3 [2] d4 a2 [2] 9a ae [2] 96 a4 [2] 81 af [2] 9a e1 [2] a7 }

  condition:
    any of them
}