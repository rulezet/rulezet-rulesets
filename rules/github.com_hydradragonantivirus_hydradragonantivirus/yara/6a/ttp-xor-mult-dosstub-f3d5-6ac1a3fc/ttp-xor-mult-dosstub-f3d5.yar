rule TTP_XOR_MULT_DOSStub_f3d5 {
  strings:
    $key_f3d5 = { a7 bd [2] d3 a5 [2] 94 a7 [2] d3 b6 [2] 9d ba [2] 91 b0 [2] 86 bb [2] 9d f5 [2] a0 }

  condition:
    any of them
}