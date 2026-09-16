rule TTP_XOR_MULT_DOSStub_be62 {
  strings:
    $key_be62 = { ea 0a [2] 9e 12 [2] d9 10 [2] 9e 01 [2] d0 0d [2] dc 07 [2] cb 0c [2] d0 42 [2] ed }

  condition:
    any of them
}