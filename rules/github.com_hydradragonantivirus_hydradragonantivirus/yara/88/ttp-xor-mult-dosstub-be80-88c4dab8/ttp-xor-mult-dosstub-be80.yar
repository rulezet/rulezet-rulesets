rule TTP_XOR_MULT_DOSStub_be80 {
  strings:
    $key_be80 = { ea e8 [2] 9e f0 [2] d9 f2 [2] 9e e3 [2] d0 ef [2] dc e5 [2] cb ee [2] d0 a0 [2] ed }

  condition:
    any of them
}