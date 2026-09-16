rule TTP_XOR_MULT_DOSStub_be86 {
  strings:
    $key_be86 = { ea ee [2] 9e f6 [2] d9 f4 [2] 9e e5 [2] d0 e9 [2] dc e3 [2] cb e8 [2] d0 a6 [2] ed }

  condition:
    any of them
}