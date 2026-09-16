rule TTP_XOR_MULT_DOSStub_5ac0 {
  strings:
    $key_5ac0 = { 0e a8 [2] 7a b0 [2] 3d b2 [2] 7a a3 [2] 34 af [2] 38 a5 [2] 2f ae [2] 34 e0 [2] 09 }

  condition:
    any of them
}