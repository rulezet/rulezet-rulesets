rule TTP_XOR_MULT_DOSStub_e0c3 {
  strings:
    $key_e0c3 = { b4 ab [2] c0 b3 [2] 87 b1 [2] c0 a0 [2] 8e ac [2] 82 a6 [2] 95 ad [2] 8e e3 [2] b3 }

  condition:
    any of them
}