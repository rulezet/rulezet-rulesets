rule TTP_XOR_MULT_DOSStub_f3d3 {
  strings:
    $key_f3d3 = { a7 bb [2] d3 a3 [2] 94 a1 [2] d3 b0 [2] 9d bc [2] 91 b6 [2] 86 bd [2] 9d f3 [2] a0 }

  condition:
    any of them
}