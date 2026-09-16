rule TTP_XOR_MULT_DOSStub_be02 {
  strings:
    $key_be02 = { ea 6a [2] 9e 72 [2] d9 70 [2] 9e 61 [2] d0 6d [2] dc 67 [2] cb 6c [2] d0 22 [2] ed }

  condition:
    any of them
}