rule TTP_XOR_MULT_DOSStub_a3f4 {
  strings:
    $key_a3f4 = { f7 9c [2] 83 84 [2] c4 86 [2] 83 97 [2] cd 9b [2] c1 91 [2] d6 9a [2] cd d4 [2] f0 }

  condition:
    any of them
}