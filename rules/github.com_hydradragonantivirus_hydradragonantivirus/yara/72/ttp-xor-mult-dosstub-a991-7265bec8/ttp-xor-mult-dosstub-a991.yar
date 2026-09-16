rule TTP_XOR_MULT_DOSStub_a991 {
  strings:
    $key_a991 = { fd f9 [2] 89 e1 [2] ce e3 [2] 89 f2 [2] c7 fe [2] cb f4 [2] dc ff [2] c7 b1 [2] fa }

  condition:
    any of them
}