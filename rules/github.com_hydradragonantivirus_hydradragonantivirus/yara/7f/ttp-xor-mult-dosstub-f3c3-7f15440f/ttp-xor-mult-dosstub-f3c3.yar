rule TTP_XOR_MULT_DOSStub_f3c3 {
  strings:
    $key_f3c3 = { a7 ab [2] d3 b3 [2] 94 b1 [2] d3 a0 [2] 9d ac [2] 91 a6 [2] 86 ad [2] 9d e3 [2] a0 }

  condition:
    any of them
}