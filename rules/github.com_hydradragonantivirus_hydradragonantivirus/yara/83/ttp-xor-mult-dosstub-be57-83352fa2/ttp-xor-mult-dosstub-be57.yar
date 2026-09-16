rule TTP_XOR_MULT_DOSStub_be57 {
  strings:
    $key_be57 = { ea 3f [2] 9e 27 [2] d9 25 [2] 9e 34 [2] d0 38 [2] dc 32 [2] cb 39 [2] d0 77 [2] ed }

  condition:
    any of them
}