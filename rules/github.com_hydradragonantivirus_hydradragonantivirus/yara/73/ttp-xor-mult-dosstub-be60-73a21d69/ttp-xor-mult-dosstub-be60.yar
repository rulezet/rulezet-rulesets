rule TTP_XOR_MULT_DOSStub_be60 {
  strings:
    $key_be60 = { ea 08 [2] 9e 10 [2] d9 12 [2] 9e 03 [2] d0 0f [2] dc 05 [2] cb 0e [2] d0 40 [2] ed }

  condition:
    any of them
}