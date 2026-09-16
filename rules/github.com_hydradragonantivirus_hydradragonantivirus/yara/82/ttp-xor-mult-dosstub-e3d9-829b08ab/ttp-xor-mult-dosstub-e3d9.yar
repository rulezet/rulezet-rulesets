rule TTP_XOR_MULT_DOSStub_e3d9 {
  strings:
    $key_e3d9 = { b7 b1 [2] c3 a9 [2] 84 ab [2] c3 ba [2] 8d b6 [2] 81 bc [2] 96 b7 [2] 8d f9 [2] b0 }

  condition:
    any of them
}