rule TTP_XOR_MULT_DOSStub_be41 {
  strings:
    $key_be41 = { ea 29 [2] 9e 31 [2] d9 33 [2] 9e 22 [2] d0 2e [2] dc 24 [2] cb 2f [2] d0 61 [2] ed }

  condition:
    any of them
}