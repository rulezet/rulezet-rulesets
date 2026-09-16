rule TTP_XOR_MULT_DOSStub_5182 {
  strings:
    $key_5182 = { 05 ea [2] 71 f2 [2] 36 f0 [2] 71 e1 [2] 3f ed [2] 33 e7 [2] 24 ec [2] 3f a2 [2] 02 }

  condition:
    any of them
}