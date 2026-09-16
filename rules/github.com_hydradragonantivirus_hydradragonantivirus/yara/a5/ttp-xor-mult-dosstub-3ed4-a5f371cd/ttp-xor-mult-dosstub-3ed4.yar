rule TTP_XOR_MULT_DOSStub_3ed4 {
  strings:
    $key_3ed4 = { 6a bc [2] 1e a4 [2] 59 a6 [2] 1e b7 [2] 50 bb [2] 5c b1 [2] 4b ba [2] 50 f4 [2] 6d }

  condition:
    any of them
}