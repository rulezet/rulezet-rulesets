rule TTP_XOR_MULT_DOSStub_be46 {
  strings:
    $key_be46 = { ea 2e [2] 9e 36 [2] d9 34 [2] 9e 25 [2] d0 29 [2] dc 23 [2] cb 28 [2] d0 66 [2] ed }

  condition:
    any of them
}