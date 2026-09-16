rule TTP_XOR_MULT_DOSStub_a5f4 {
  strings:
    $key_a5f4 = { f1 9c [2] 85 84 [2] c2 86 [2] 85 97 [2] cb 9b [2] c7 91 [2] d0 9a [2] cb d4 [2] f6 }

  condition:
    any of them
}