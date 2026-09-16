rule TTP_XOR_MULT_DOSStub_be87 {
  strings:
    $key_be87 = { ea ef [2] 9e f7 [2] d9 f5 [2] 9e e4 [2] d0 e8 [2] dc e2 [2] cb e9 [2] d0 a7 [2] ed }

  condition:
    any of them
}