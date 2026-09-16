rule TTP_XOR_MULT_DOSStub_be1a {
  strings:
    $key_be1a = { ea 72 [2] 9e 6a [2] d9 68 [2] 9e 79 [2] d0 75 [2] dc 7f [2] cb 74 [2] d0 3a [2] ed }

  condition:
    any of them
}