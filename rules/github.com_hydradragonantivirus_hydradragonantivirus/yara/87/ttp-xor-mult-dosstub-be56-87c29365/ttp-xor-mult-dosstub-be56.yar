rule TTP_XOR_MULT_DOSStub_be56 {
  strings:
    $key_be56 = { ea 3e [2] 9e 26 [2] d9 24 [2] 9e 35 [2] d0 39 [2] dc 33 [2] cb 38 [2] d0 76 [2] ed }

  condition:
    any of them
}