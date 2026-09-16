rule TTP_XOR_MULT_DOSStub_38d9 {
  strings:
    $key_38d9 = { 6c b1 [2] 18 a9 [2] 5f ab [2] 18 ba [2] 56 b6 [2] 5a bc [2] 4d b7 [2] 56 f9 [2] 6b }

  condition:
    any of them
}