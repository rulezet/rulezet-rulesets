rule TTP_XOR_MULT_DOSStub_a5e8 {
  strings:
    $key_a5e8 = { f1 80 [2] 85 98 [2] c2 9a [2] 85 8b [2] cb 87 [2] c7 8d [2] d0 86 [2] cb c8 [2] f6 }

  condition:
    any of them
}