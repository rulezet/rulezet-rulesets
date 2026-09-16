rule TTP_XOR_MULT_DOSStub_a56e {
  strings:
    $key_a56e = { f1 06 [2] 85 1e [2] c2 1c [2] 85 0d [2] cb 01 [2] c7 0b [2] d0 00 [2] cb 4e [2] f6 }

  condition:
    any of them
}