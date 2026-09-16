rule TTP_XOR_MULT_DOSStub_f387 {
  strings:
    $key_f387 = { a7 ef [2] d3 f7 [2] 94 f5 [2] d3 e4 [2] 9d e8 [2] 91 e2 [2] 86 e9 [2] 9d a7 [2] a0 }

  condition:
    any of them
}