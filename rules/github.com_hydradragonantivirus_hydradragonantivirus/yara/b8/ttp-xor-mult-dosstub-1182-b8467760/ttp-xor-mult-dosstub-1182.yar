rule TTP_XOR_MULT_DOSStub_1182 {
  strings:
    $key_1182 = { 45 ea [2] 31 f2 [2] 76 f0 [2] 31 e1 [2] 7f ed [2] 73 e7 [2] 64 ec [2] 7f a2 [2] 42 }

  condition:
    any of them
}