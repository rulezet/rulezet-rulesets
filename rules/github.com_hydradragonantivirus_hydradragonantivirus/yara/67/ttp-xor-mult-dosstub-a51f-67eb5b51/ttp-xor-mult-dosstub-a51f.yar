rule TTP_XOR_MULT_DOSStub_a51f {
  strings:
    $key_a51f = { f1 77 [2] 85 6f [2] c2 6d [2] 85 7c [2] cb 70 [2] c7 7a [2] d0 71 [2] cb 3f [2] f6 }

  condition:
    any of them
}