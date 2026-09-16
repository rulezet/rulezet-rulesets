rule TTP_XOR_MULT_DOSStub_34d3 {
  strings:
    $key_34d3 = { 60 bb [2] 14 a3 [2] 53 a1 [2] 14 b0 [2] 5a bc [2] 56 b6 [2] 41 bd [2] 5a f3 [2] 67 }

  condition:
    any of them
}