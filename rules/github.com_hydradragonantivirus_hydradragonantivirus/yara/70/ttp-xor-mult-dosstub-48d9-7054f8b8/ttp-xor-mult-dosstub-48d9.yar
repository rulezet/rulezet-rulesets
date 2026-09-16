rule TTP_XOR_MULT_DOSStub_48d9 {
  strings:
    $key_48d9 = { 1c b1 [2] 68 a9 [2] 2f ab [2] 68 ba [2] 26 b6 [2] 2a bc [2] 3d b7 [2] 26 f9 [2] 1b }

  condition:
    any of them
}