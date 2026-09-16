rule TTP_XOR_MULT_DOSStub_3182 {
  strings:
    $key_3182 = { 65 ea [2] 11 f2 [2] 56 f0 [2] 11 e1 [2] 5f ed [2] 53 e7 [2] 44 ec [2] 5f a2 [2] 62 }

  condition:
    any of them
}