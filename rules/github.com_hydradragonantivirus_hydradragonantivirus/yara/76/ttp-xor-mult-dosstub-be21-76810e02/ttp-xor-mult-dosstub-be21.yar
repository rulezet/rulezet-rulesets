rule TTP_XOR_MULT_DOSStub_be21 {
  strings:
    $key_be21 = { ea 49 [2] 9e 51 [2] d9 53 [2] 9e 42 [2] d0 4e [2] dc 44 [2] cb 4f [2] d0 01 [2] ed }

  condition:
    any of them
}