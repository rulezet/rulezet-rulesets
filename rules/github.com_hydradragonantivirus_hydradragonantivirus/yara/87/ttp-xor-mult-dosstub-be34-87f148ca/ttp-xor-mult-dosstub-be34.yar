rule TTP_XOR_MULT_DOSStub_be34 {
  strings:
    $key_be34 = { ea 5c [2] 9e 44 [2] d9 46 [2] 9e 57 [2] d0 5b [2] dc 51 [2] cb 5a [2] d0 14 [2] ed }

  condition:
    any of them
}