rule TTP_XOR_MULT_DOSStub_a5e3 {
  strings:
    $key_a5e3 = { f1 8b [2] 85 93 [2] c2 91 [2] 85 80 [2] cb 8c [2] c7 86 [2] d0 8d [2] cb c3 [2] f6 }

  condition:
    any of them
}