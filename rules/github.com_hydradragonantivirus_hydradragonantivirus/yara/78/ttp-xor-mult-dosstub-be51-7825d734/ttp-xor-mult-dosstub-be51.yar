rule TTP_XOR_MULT_DOSStub_be51 {
  strings:
    $key_be51 = { ea 39 [2] 9e 21 [2] d9 23 [2] 9e 32 [2] d0 3e [2] dc 34 [2] cb 3f [2] d0 71 [2] ed }

  condition:
    any of them
}