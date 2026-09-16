rule TTP_XOR_MULT_DOSStub_be54 {
  strings:
    $key_be54 = { ea 3c [2] 9e 24 [2] d9 26 [2] 9e 37 [2] d0 3b [2] dc 31 [2] cb 3a [2] d0 74 [2] ed }

  condition:
    any of them
}