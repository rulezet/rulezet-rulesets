rule TTP_XOR_MULT_DOSStub_e0c0 {
  strings:
    $key_e0c0 = { b4 a8 [2] c0 b0 [2] 87 b2 [2] c0 a3 [2] 8e af [2] 82 a5 [2] 95 ae [2] 8e e0 [2] b3 }

  condition:
    any of them
}