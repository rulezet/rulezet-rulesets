rule TTP_XOR_MULT_DOSStub_f3c1 {
  strings:
    $key_f3c1 = { a7 a9 [2] d3 b1 [2] 94 b3 [2] d3 a2 [2] 9d ae [2] 91 a4 [2] 86 af [2] 9d e1 [2] a0 }

  condition:
    any of them
}