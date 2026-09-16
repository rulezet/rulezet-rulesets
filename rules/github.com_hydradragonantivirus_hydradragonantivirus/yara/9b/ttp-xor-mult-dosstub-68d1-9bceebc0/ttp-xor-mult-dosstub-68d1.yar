rule TTP_XOR_MULT_DOSStub_68d1 {
  strings:
    $key_68d1 = { 3c b9 [2] 48 a1 [2] 0f a3 [2] 48 b2 [2] 06 be [2] 0a b4 [2] 1d bf [2] 06 f1 [2] 3b }

  condition:
    any of them
}