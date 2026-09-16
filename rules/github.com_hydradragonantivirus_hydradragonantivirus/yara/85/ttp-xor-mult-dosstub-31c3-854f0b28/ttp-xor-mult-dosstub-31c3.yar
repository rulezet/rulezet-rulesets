rule TTP_XOR_MULT_DOSStub_31c3 {
  strings:
    $key_31c3 = { 65 ab [2] 11 b3 [2] 56 b1 [2] 11 a0 [2] 5f ac [2] 53 a6 [2] 44 ad [2] 5f e3 [2] 62 }

  condition:
    any of them
}