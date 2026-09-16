rule TTP_XOR_MULT_DOSStub_a5ea {
  strings:
    $key_a5ea = { f1 82 [2] 85 9a [2] c2 98 [2] 85 89 [2] cb 85 [2] c7 8f [2] d0 84 [2] cb ca [2] f6 }

  condition:
    any of them
}