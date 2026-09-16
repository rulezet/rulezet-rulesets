rule TTP_XOR_MULT_DOSStub_e082 {
  strings:
    $key_e082 = { b4 ea [2] c0 f2 [2] 87 f0 [2] c0 e1 [2] 8e ed [2] 82 e7 [2] 95 ec [2] 8e a2 [2] b3 }

  condition:
    any of them
}