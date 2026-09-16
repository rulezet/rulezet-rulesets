rule TTP_XOR_MULT_DOSStub_a5fc {
  strings:
    $key_a5fc = { f1 94 [2] 85 8c [2] c2 8e [2] 85 9f [2] cb 93 [2] c7 99 [2] d0 92 [2] cb dc [2] f6 }

  condition:
    any of them
}