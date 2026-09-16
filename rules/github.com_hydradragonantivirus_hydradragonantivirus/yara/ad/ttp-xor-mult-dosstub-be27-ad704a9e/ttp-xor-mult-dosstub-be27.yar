rule TTP_XOR_MULT_DOSStub_be27 {
  strings:
    $key_be27 = { ea 4f [2] 9e 57 [2] d9 55 [2] 9e 44 [2] d0 48 [2] dc 42 [2] cb 49 [2] d0 07 [2] ed }

  condition:
    any of them
}