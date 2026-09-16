rule TTP_XOR_MULT_DOSStub_f3c8 {
  strings:
    $key_f3c8 = { a7 a0 [2] d3 b8 [2] 94 ba [2] d3 ab [2] 9d a7 [2] 91 ad [2] 86 a6 [2] 9d e8 [2] a0 }

  condition:
    any of them
}