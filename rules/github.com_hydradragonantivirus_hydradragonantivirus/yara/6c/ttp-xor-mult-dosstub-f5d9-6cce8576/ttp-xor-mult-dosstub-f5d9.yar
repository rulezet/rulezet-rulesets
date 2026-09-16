rule TTP_XOR_MULT_DOSStub_f5d9 {
  strings:
    $key_f5d9 = { a1 b1 [2] d5 a9 [2] 92 ab [2] d5 ba [2] 9b b6 [2] 97 bc [2] 80 b7 [2] 9b f9 [2] a6 }

  condition:
    any of them
}