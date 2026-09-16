rule TTP_XOR_MULT_DOSStub_a522 {
  strings:
    $key_a522 = { f1 4a [2] 85 52 [2] c2 50 [2] 85 41 [2] cb 4d [2] c7 47 [2] d0 4c [2] cb 02 [2] f6 }

  condition:
    any of them
}