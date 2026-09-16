rule TTP_XOR_MULT_DOSStub_5ed9 {
  strings:
    $key_5ed9 = { 0a b1 [2] 7e a9 [2] 39 ab [2] 7e ba [2] 30 b6 [2] 3c bc [2] 2b b7 [2] 30 f9 [2] 0d }

  condition:
    any of them
}