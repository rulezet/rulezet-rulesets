rule TTP_XOR_MULT_DOSStub_be38 {
  strings:
    $key_be38 = { ea 50 [2] 9e 48 [2] d9 4a [2] 9e 5b [2] d0 57 [2] dc 5d [2] cb 56 [2] d0 18 [2] ed }

  condition:
    any of them
}