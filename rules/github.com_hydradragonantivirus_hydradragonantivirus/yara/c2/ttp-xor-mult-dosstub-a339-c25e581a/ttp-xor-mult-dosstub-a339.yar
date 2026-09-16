rule TTP_XOR_MULT_DOSStub_a339 {
  strings:
    $key_a339 = { f7 51 [2] 83 49 [2] c4 4b [2] 83 5a [2] cd 56 [2] c1 5c [2] d6 57 [2] cd 19 [2] f0 }

  condition:
    any of them
}