rule TTP_XOR_MULT_DOSStub_be19 {
  strings:
    $key_be19 = { ea 71 [2] 9e 69 [2] d9 6b [2] 9e 7a [2] d0 76 [2] dc 7c [2] cb 77 [2] d0 39 [2] ed }

  condition:
    any of them
}