rule TTP_XOR_MULT_DOSStub_be69 {
  strings:
    $key_be69 = { ea 01 [2] 9e 19 [2] d9 1b [2] 9e 0a [2] d0 06 [2] dc 0c [2] cb 07 [2] d0 49 [2] ed }

  condition:
    any of them
}