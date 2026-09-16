rule TTP_XOR_MULT_DOSStub_6ec0 {
  strings:
    $key_6ec0 = { 3a a8 [2] 4e b0 [2] 09 b2 [2] 4e a3 [2] 00 af [2] 0c a5 [2] 1b ae [2] 00 e0 [2] 3d }

  condition:
    any of them
}