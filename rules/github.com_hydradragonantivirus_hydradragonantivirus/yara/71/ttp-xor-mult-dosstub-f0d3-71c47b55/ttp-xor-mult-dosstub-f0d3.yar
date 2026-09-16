rule TTP_XOR_MULT_DOSStub_f0d3 {
  strings:
    $key_f0d3 = { a4 bb [2] d0 a3 [2] 97 a1 [2] d0 b0 [2] 9e bc [2] 92 b6 [2] 85 bd [2] 9e f3 [2] a3 }

  condition:
    any of them
}