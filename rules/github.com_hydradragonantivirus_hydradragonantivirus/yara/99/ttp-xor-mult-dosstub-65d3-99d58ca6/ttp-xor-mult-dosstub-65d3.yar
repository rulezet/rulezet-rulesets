rule TTP_XOR_MULT_DOSStub_65d3 {
  strings:
    $key_65d3 = { 31 bb [2] 45 a3 [2] 02 a1 [2] 45 b0 [2] 0b bc [2] 07 b6 [2] 10 bd [2] 0b f3 [2] 36 }

  condition:
    any of them
}