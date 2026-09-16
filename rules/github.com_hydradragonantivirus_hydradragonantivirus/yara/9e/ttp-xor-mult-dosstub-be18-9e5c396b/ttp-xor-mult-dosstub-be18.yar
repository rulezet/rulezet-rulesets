rule TTP_XOR_MULT_DOSStub_be18 {
  strings:
    $key_be18 = { ea 70 [2] 9e 68 [2] d9 6a [2] 9e 7b [2] d0 77 [2] dc 7d [2] cb 76 [2] d0 38 [2] ed }

  condition:
    any of them
}