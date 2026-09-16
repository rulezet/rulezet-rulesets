rule TTP_XOR_MULT_DOSStub_78d9 {
  strings:
    $key_78d9 = { 2c b1 [2] 58 a9 [2] 1f ab [2] 58 ba [2] 16 b6 [2] 1a bc [2] 0d b7 [2] 16 f9 [2] 2b }

  condition:
    any of them
}