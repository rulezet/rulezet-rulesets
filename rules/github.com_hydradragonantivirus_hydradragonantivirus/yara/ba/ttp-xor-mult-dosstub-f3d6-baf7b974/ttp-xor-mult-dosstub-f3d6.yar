rule TTP_XOR_MULT_DOSStub_f3d6 {
  strings:
    $key_f3d6 = { a7 be [2] d3 a6 [2] 94 a4 [2] d3 b5 [2] 9d b9 [2] 91 b3 [2] 86 b8 [2] 9d f6 [2] a0 }

  condition:
    any of them
}