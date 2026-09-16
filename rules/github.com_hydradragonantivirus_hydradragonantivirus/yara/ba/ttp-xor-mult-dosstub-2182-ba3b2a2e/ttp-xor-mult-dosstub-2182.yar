rule TTP_XOR_MULT_DOSStub_2182 {
  strings:
    $key_2182 = { 75 ea [2] 01 f2 [2] 46 f0 [2] 01 e1 [2] 4f ed [2] 43 e7 [2] 54 ec [2] 4f a2 [2] 72 }

  condition:
    any of them
}