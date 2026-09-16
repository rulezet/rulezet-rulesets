rule TTP_XOR_MULT_DOSStub_be08 {
  strings:
    $key_be08 = { ea 60 [2] 9e 78 [2] d9 7a [2] 9e 6b [2] d0 67 [2] dc 6d [2] cb 66 [2] d0 28 [2] ed }

  condition:
    any of them
}