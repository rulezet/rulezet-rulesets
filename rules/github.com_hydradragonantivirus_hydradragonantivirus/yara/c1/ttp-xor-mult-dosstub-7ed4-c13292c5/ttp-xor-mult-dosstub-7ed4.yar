rule TTP_XOR_MULT_DOSStub_7ed4 {
  strings:
    $key_7ed4 = { 2a bc [2] 5e a4 [2] 19 a6 [2] 5e b7 [2] 10 bb [2] 1c b1 [2] 0b ba [2] 10 f4 [2] 2d }

  condition:
    any of them
}