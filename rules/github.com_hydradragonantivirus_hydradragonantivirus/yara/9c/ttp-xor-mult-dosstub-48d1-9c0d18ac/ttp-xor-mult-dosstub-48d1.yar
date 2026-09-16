rule TTP_XOR_MULT_DOSStub_48d1 {
  strings:
    $key_48d1 = { 1c b9 [2] 68 a1 [2] 2f a3 [2] 68 b2 [2] 26 be [2] 2a b4 [2] 3d bf [2] 26 f1 [2] 1b }

  condition:
    any of them
}