rule TTP_XOR_MULT_DOSStub_f3c7 {
  strings:
    $key_f3c7 = { a7 af [2] d3 b7 [2] 94 b5 [2] d3 a4 [2] 9d a8 [2] 91 a2 [2] 86 a9 [2] 9d e7 [2] a0 }

  condition:
    any of them
}