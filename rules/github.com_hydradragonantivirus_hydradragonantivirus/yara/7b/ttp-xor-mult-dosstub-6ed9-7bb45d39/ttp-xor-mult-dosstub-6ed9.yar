rule TTP_XOR_MULT_DOSStub_6ed9 {
  strings:
    $key_6ed9 = { 3a b1 [2] 4e a9 [2] 09 ab [2] 4e ba [2] 00 b6 [2] 0c bc [2] 1b b7 [2] 00 f9 [2] 3d }

  condition:
    any of them
}