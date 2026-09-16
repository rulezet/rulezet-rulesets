rule TTP_XOR_MULT_DOSStub_be59 {
  strings:
    $key_be59 = { ea 31 [2] 9e 29 [2] d9 2b [2] 9e 3a [2] d0 36 [2] dc 3c [2] cb 37 [2] d0 79 [2] ed }

  condition:
    any of them
}