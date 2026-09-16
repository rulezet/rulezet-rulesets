rule TTP_XOR_MULT_DOSStub_f4c3 {
  strings:
    $key_f4c3 = { a0 ab [2] d4 b3 [2] 93 b1 [2] d4 a0 [2] 9a ac [2] 96 a6 [2] 81 ad [2] 9a e3 [2] a7 }

  condition:
    any of them
}