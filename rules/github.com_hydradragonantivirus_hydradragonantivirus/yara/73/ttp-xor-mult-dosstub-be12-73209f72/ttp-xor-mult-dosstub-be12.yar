rule TTP_XOR_MULT_DOSStub_be12 {
  strings:
    $key_be12 = { ea 7a [2] 9e 62 [2] d9 60 [2] 9e 71 [2] d0 7d [2] dc 77 [2] cb 7c [2] d0 32 [2] ed }

  condition:
    any of them
}