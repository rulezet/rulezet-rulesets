rule TTP_XOR_MULT_DOSStub_be48 {
  strings:
    $key_be48 = { ea 20 [2] 9e 38 [2] d9 3a [2] 9e 2b [2] d0 27 [2] dc 2d [2] cb 26 [2] d0 68 [2] ed }

  condition:
    any of them
}