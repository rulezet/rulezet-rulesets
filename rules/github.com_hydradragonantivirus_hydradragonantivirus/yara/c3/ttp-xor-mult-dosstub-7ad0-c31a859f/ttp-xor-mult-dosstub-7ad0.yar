rule TTP_XOR_MULT_DOSStub_7ad0 {
  strings:
    $key_7ad0 = { 2e b8 [2] 5a a0 [2] 1d a2 [2] 5a b3 [2] 14 bf [2] 18 b5 [2] 0f be [2] 14 f0 [2] 29 }

  condition:
    any of them
}