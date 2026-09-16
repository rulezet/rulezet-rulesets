rule TTP_XOR_MULT_DOSStub_28d9 {
  strings:
    $key_28d9 = { 7c b1 [2] 08 a9 [2] 4f ab [2] 08 ba [2] 46 b6 [2] 4a bc [2] 5d b7 [2] 46 f9 [2] 7b }

  condition:
    any of them
}