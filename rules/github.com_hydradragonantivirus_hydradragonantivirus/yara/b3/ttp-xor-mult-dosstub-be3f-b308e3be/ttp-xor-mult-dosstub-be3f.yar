rule TTP_XOR_MULT_DOSStub_be3f {
  strings:
    $key_be3f = { ea 57 [2] 9e 4f [2] d9 4d [2] 9e 5c [2] d0 50 [2] dc 5a [2] cb 51 [2] d0 1f [2] ed }

  condition:
    any of them
}