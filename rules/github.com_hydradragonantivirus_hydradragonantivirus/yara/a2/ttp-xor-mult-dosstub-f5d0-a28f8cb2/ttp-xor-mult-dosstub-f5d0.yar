rule TTP_XOR_MULT_DOSStub_f5d0 {
  strings:
    $key_f5d0 = { a1 b8 [2] d5 a0 [2] 92 a2 [2] d5 b3 [2] 9b bf [2] 97 b5 [2] 80 be [2] 9b f0 [2] a6 }

  condition:
    any of them
}