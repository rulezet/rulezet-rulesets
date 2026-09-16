rule TTP_XOR_MULT_DOSStub_be16 {
  strings:
    $key_be16 = { ea 7e [2] 9e 66 [2] d9 64 [2] 9e 75 [2] d0 79 [2] dc 73 [2] cb 78 [2] d0 36 [2] ed }

  condition:
    any of them
}