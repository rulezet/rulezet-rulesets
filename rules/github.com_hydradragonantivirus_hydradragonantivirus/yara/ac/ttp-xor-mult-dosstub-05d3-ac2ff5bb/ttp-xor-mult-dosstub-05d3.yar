rule TTP_XOR_MULT_DOSStub_05d3 {
  strings:
    $key_05d3 = { 51 bb [2] 25 a3 [2] 62 a1 [2] 25 b0 [2] 6b bc [2] 67 b6 [2] 70 bd [2] 6b f3 [2] 56 }

  condition:
    any of them
}