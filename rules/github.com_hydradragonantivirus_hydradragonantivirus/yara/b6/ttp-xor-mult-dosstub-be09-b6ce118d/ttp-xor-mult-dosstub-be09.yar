rule TTP_XOR_MULT_DOSStub_be09 {
  strings:
    $key_be09 = { ea 61 [2] 9e 79 [2] d9 7b [2] 9e 6a [2] d0 66 [2] dc 6c [2] cb 67 [2] d0 29 [2] ed }

  condition:
    any of them
}