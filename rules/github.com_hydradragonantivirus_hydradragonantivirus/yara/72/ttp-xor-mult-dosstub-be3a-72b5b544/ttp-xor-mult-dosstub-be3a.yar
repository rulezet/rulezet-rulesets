rule TTP_XOR_MULT_DOSStub_be3a {
  strings:
    $key_be3a = { ea 52 [2] 9e 4a [2] d9 48 [2] 9e 59 [2] d0 55 [2] dc 5f [2] cb 54 [2] d0 1a [2] ed }

  condition:
    any of them
}