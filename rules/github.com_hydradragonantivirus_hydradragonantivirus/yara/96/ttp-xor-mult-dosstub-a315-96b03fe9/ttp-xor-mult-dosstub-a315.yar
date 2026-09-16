rule TTP_XOR_MULT_DOSStub_a315 {
  strings:
    $key_a315 = { f7 7d [2] 83 65 [2] c4 67 [2] 83 76 [2] cd 7a [2] c1 70 [2] d6 7b [2] cd 35 [2] f0 }

  condition:
    any of them
}