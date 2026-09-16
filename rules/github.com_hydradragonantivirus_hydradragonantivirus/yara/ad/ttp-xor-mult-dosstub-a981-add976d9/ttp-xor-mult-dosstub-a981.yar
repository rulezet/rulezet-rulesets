rule TTP_XOR_MULT_DOSStub_a981 {
  strings:
    $key_a981 = { fd e9 [2] 89 f1 [2] ce f3 [2] 89 e2 [2] c7 ee [2] cb e4 [2] dc ef [2] c7 a1 [2] fa }

  condition:
    any of them
}