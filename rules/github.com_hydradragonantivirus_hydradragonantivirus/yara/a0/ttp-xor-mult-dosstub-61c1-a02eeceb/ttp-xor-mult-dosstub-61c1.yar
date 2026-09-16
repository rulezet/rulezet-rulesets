rule TTP_XOR_MULT_DOSStub_61c1 {
  strings:
    $key_61c1 = { 35 a9 [2] 41 b1 [2] 06 b3 [2] 41 a2 [2] 0f ae [2] 03 a4 [2] 14 af [2] 0f e1 [2] 32 }

  condition:
    any of them
}