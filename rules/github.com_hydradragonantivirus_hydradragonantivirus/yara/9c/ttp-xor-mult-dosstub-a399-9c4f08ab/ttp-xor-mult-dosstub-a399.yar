rule TTP_XOR_MULT_DOSStub_a399 {
  strings:
    $key_a399 = { f7 f1 [2] 83 e9 [2] c4 eb [2] 83 fa [2] cd f6 [2] c1 fc [2] d6 f7 [2] cd b9 [2] f0 }

  condition:
    any of them
}