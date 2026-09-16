rule TTP_XOR_MULT_DOSStub_bee7 {
  strings:
    $key_bee7 = { ea 8f [2] 9e 97 [2] d9 95 [2] 9e 84 [2] d0 88 [2] dc 82 [2] cb 89 [2] d0 c7 [2] ed }

  condition:
    any of them
}