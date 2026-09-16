rule TTP_XOR_MULT_DOSStub_0ac0 {
  strings:
    $key_0ac0 = { 5e a8 [2] 2a b0 [2] 6d b2 [2] 2a a3 [2] 64 af [2] 68 a5 [2] 7f ae [2] 64 e0 [2] 59 }

  condition:
    any of them
}