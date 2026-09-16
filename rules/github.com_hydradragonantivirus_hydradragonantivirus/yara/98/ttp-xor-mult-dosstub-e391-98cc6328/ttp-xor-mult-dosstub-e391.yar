rule TTP_XOR_MULT_DOSStub_e391 {
  strings:
    $key_e391 = { b7 f9 [2] c3 e1 [2] 84 e3 [2] c3 f2 [2] 8d fe [2] 81 f4 [2] 96 ff [2] 8d b1 [2] b0 }

  condition:
    any of them
}