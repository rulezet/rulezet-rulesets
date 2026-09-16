rule TTP_XOR_MULT_DOSStub_a3d4 {
  strings:
    $key_a3d4 = { f7 bc [2] 83 a4 [2] c4 a6 [2] 83 b7 [2] cd bb [2] c1 b1 [2] d6 ba [2] cd f4 [2] f0 }

  condition:
    any of them
}