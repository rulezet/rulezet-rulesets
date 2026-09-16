rule TTP_XOR_MULT_DOSStub_be55 {
  strings:
    $key_be55 = { ea 3d [2] 9e 25 [2] d9 27 [2] 9e 36 [2] d0 3a [2] dc 30 [2] cb 3b [2] d0 75 [2] ed }

  condition:
    any of them
}