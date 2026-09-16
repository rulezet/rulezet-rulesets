rule TTP_XOR_MULT_DOSStub_e3d0 {
  strings:
    $key_e3d0 = { b7 b8 [2] c3 a0 [2] 84 a2 [2] c3 b3 [2] 8d bf [2] 81 b5 [2] 96 be [2] 8d f0 [2] b0 }

  condition:
    any of them
}