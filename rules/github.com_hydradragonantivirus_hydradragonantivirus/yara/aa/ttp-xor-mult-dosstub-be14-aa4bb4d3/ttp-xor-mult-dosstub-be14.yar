rule TTP_XOR_MULT_DOSStub_be14 {
  strings:
    $key_be14 = { ea 7c [2] 9e 64 [2] d9 66 [2] 9e 77 [2] d0 7b [2] dc 71 [2] cb 7a [2] d0 34 [2] ed }

  condition:
    any of them
}