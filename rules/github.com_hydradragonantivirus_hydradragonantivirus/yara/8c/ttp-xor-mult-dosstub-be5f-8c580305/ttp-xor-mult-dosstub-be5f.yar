rule TTP_XOR_MULT_DOSStub_be5f {
  strings:
    $key_be5f = { ea 37 [2] 9e 2f [2] d9 2d [2] 9e 3c [2] d0 30 [2] dc 3a [2] cb 31 [2] d0 7f [2] ed }

  condition:
    any of them
}