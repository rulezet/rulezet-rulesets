rule TTP_XOR_MULT_DOSStub_f0d2 {
  strings:
    $key_f0d2 = { a4 ba [2] d0 a2 [2] 97 a0 [2] d0 b1 [2] 9e bd [2] 92 b7 [2] 85 bc [2] 9e f2 [2] a3 }

  condition:
    any of them
}