rule TTP_XOR_MULT_DOSStub_a32a {
  strings:
    $key_a32a = { f7 42 [2] 83 5a [2] c4 58 [2] 83 49 [2] cd 45 [2] c1 4f [2] d6 44 [2] cd 0a [2] f0 }

  condition:
    any of them
}