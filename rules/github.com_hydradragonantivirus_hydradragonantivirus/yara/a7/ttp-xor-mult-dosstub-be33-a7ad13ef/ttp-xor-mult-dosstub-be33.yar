rule TTP_XOR_MULT_DOSStub_be33 {
  strings:
    $key_be33 = { ea 5b [2] 9e 43 [2] d9 41 [2] 9e 50 [2] d0 5c [2] dc 56 [2] cb 5d [2] d0 13 [2] ed }

  condition:
    any of them
}