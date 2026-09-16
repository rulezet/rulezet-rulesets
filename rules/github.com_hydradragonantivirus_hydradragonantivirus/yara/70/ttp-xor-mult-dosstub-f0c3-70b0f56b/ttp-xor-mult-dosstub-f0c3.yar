rule TTP_XOR_MULT_DOSStub_f0c3 {
  strings:
    $key_f0c3 = { a4 ab [2] d0 b3 [2] 97 b1 [2] d0 a0 [2] 9e ac [2] 92 a6 [2] 85 ad [2] 9e e3 [2] a3 }

  condition:
    any of them
}