rule TTP_XOR_MULT_DOSStub_6ed4 {
  strings:
    $key_6ed4 = { 3a bc [2] 4e a4 [2] 09 a6 [2] 4e b7 [2] 00 bb [2] 0c b1 [2] 1b ba [2] 00 f4 [2] 3d }

  condition:
    any of them
}