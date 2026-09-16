rule TTP_XOR_MULT_DOSStub_e784 {
  strings:
    $key_e784 = { b3 ec [2] c7 f4 [2] 80 f6 [2] c7 e7 [2] 89 eb [2] 85 e1 [2] 92 ea [2] 89 a4 [2] b4 }

  condition:
    any of them
}