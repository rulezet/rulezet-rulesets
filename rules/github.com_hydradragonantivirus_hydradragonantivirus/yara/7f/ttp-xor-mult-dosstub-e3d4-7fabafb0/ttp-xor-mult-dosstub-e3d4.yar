rule TTP_XOR_MULT_DOSStub_e3d4 {
  strings:
    $key_e3d4 = { b7 bc [2] c3 a4 [2] 84 a6 [2] c3 b7 [2] 8d bb [2] 81 b1 [2] 96 ba [2] 8d f4 [2] b0 }

  condition:
    any of them
}