rule TTP_XOR_MULT_DOSStub_f3d8 {
  strings:
    $key_f3d8 = { a7 b0 [2] d3 a8 [2] 94 aa [2] d3 bb [2] 9d b7 [2] 91 bd [2] 86 b6 [2] 9d f8 [2] a0 }

  condition:
    any of them
}