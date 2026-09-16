rule TTP_XOR_MULT_DOSStub_be50 {
  strings:
    $key_be50 = { ea 38 [2] 9e 20 [2] d9 22 [2] 9e 33 [2] d0 3f [2] dc 35 [2] cb 3e [2] d0 70 [2] ed }

  condition:
    any of them
}