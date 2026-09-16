rule TTP_XOR_MULT_DOSStub_bee4 {
  strings:
    $key_bee4 = { ea 8c [2] 9e 94 [2] d9 96 [2] 9e 87 [2] d0 8b [2] dc 81 [2] cb 8a [2] d0 c4 [2] ed }

  condition:
    any of them
}