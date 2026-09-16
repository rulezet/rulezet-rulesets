rule TTP_XOR_MULT_DOSStub_e4c3 {
  strings:
    $key_e4c3 = { b0 ab [2] c4 b3 [2] 83 b1 [2] c4 a0 [2] 8a ac [2] 86 a6 [2] 91 ad [2] 8a e3 [2] b7 }

  condition:
    any of them
}