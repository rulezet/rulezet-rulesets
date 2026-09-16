rule TTP_XOR_MULT_DOSStub_f3d0 {
  strings:
    $key_f3d0 = { a7 b8 [2] d3 a0 [2] 94 a2 [2] d3 b3 [2] 9d bf [2] 91 b5 [2] 86 be [2] 9d f0 [2] a0 }

  condition:
    any of them
}