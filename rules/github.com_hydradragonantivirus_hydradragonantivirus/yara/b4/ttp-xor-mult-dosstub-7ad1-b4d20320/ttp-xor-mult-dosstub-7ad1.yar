rule TTP_XOR_MULT_DOSStub_7ad1 {
  strings:
    $key_7ad1 = { 2e b9 [2] 5a a1 [2] 1d a3 [2] 5a b2 [2] 14 be [2] 18 b4 [2] 0f bf [2] 14 f1 [2] 29 }

  condition:
    any of them
}