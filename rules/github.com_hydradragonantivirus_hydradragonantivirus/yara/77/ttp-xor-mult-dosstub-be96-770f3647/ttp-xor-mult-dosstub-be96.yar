rule TTP_XOR_MULT_DOSStub_be96 {
  strings:
    $key_be96 = { ea fe [2] 9e e6 [2] d9 e4 [2] 9e f5 [2] d0 f9 [2] dc f3 [2] cb f8 [2] d0 b6 [2] ed }

  condition:
    any of them
}