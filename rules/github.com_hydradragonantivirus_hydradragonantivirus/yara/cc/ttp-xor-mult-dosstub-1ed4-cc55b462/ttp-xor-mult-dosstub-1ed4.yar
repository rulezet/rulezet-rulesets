rule TTP_XOR_MULT_DOSStub_1ed4 {
  strings:
    $key_1ed4 = { 4a bc [2] 3e a4 [2] 79 a6 [2] 3e b7 [2] 70 bb [2] 7c b1 [2] 6b ba [2] 70 f4 [2] 4d }

  condition:
    any of them
}