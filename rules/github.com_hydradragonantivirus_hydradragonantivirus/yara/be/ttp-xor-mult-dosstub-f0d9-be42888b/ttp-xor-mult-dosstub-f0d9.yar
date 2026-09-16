rule TTP_XOR_MULT_DOSStub_f0d9 {
  strings:
    $key_f0d9 = { a4 b1 [2] d0 a9 [2] 97 ab [2] d0 ba [2] 9e b6 [2] 92 bc [2] 85 b7 [2] 9e f9 [2] a3 }

  condition:
    any of them
}