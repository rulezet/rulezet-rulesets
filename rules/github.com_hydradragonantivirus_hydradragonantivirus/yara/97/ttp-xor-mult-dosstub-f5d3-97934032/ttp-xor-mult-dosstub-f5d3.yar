rule TTP_XOR_MULT_DOSStub_f5d3 {
  strings:
    $key_f5d3 = { a1 bb [2] d5 a3 [2] 92 a1 [2] d5 b0 [2] 9b bc [2] 97 b6 [2] 80 bd [2] 9b f3 [2] a6 }

  condition:
    any of them
}