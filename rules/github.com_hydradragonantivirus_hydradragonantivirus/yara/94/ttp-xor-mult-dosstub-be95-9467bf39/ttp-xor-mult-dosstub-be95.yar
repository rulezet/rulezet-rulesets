rule TTP_XOR_MULT_DOSStub_be95 {
  strings:
    $key_be95 = { ea fd [2] 9e e5 [2] d9 e7 [2] 9e f6 [2] d0 fa [2] dc f0 [2] cb fb [2] d0 b5 [2] ed }

  condition:
    any of them
}