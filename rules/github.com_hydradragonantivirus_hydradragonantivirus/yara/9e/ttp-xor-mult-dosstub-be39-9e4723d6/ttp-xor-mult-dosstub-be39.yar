rule TTP_XOR_MULT_DOSStub_be39 {
  strings:
    $key_be39 = { ea 51 [2] 9e 49 [2] d9 4b [2] 9e 5a [2] d0 56 [2] dc 5c [2] cb 57 [2] d0 19 [2] ed }

  condition:
    any of them
}