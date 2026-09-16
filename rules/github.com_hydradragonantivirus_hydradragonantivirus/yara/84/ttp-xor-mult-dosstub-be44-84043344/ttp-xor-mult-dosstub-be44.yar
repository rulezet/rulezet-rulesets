rule TTP_XOR_MULT_DOSStub_be44 {
  strings:
    $key_be44 = { ea 2c [2] 9e 34 [2] d9 36 [2] 9e 27 [2] d0 2b [2] dc 21 [2] cb 2a [2] d0 64 [2] ed }

  condition:
    any of them
}