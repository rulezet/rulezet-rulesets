rule TTP_XOR_MULT_DOSStub_e3c7 {
  strings:
    $key_e3c7 = { b7 af [2] c3 b7 [2] 84 b5 [2] c3 a4 [2] 8d a8 [2] 81 a2 [2] 96 a9 [2] 8d e7 [2] b0 }

  condition:
    any of them
}