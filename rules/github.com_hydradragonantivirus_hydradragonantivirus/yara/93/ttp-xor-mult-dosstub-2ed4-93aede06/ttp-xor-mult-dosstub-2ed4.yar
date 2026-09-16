rule TTP_XOR_MULT_DOSStub_2ed4 {
  strings:
    $key_2ed4 = { 7a bc [2] 0e a4 [2] 49 a6 [2] 0e b7 [2] 40 bb [2] 4c b1 [2] 5b ba [2] 40 f4 [2] 7d }

  condition:
    any of them
}