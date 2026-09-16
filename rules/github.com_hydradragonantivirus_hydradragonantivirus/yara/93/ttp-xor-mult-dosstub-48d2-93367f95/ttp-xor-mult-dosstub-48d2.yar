rule TTP_XOR_MULT_DOSStub_48d2 {
  strings:
    $key_48d2 = { 1c ba [2] 68 a2 [2] 2f a0 [2] 68 b1 [2] 26 bd [2] 2a b7 [2] 3d bc [2] 26 f2 [2] 1b }

  condition:
    any of them
}