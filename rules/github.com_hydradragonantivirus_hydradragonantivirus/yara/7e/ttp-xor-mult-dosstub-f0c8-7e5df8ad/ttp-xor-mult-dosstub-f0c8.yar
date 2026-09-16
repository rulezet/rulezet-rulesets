rule TTP_XOR_MULT_DOSStub_f0c8 {
  strings:
    $key_f0c8 = { a4 a0 [2] d0 b8 [2] 97 ba [2] d0 ab [2] 9e a7 [2] 92 ad [2] 85 a6 [2] 9e e8 [2] a3 }

  condition:
    any of them
}