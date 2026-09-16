rule TTP_XOR_MULT_DOSStub_be37 {
  strings:
    $key_be37 = { ea 5f [2] 9e 47 [2] d9 45 [2] 9e 54 [2] d0 58 [2] dc 52 [2] cb 59 [2] d0 17 [2] ed }

  condition:
    any of them
}