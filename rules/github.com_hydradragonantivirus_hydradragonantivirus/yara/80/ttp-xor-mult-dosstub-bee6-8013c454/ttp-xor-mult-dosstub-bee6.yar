rule TTP_XOR_MULT_DOSStub_bee6 {
  strings:
    $key_bee6 = { ea 8e [2] 9e 96 [2] d9 94 [2] 9e 85 [2] d0 89 [2] dc 83 [2] cb 88 [2] d0 c6 [2] ed }

  condition:
    any of them
}