rule TTP_XOR_MULT_DOSStub_58d9 {
  strings:
    $key_58d9 = { 0c b1 [2] 78 a9 [2] 3f ab [2] 78 ba [2] 36 b6 [2] 3a bc [2] 2d b7 [2] 36 f9 [2] 0b }

  condition:
    any of them
}