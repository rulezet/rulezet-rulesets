rule TTP_XOR_MULT_DOSStub_a36a {
  strings:
    $key_a36a = { f7 02 [2] 83 1a [2] c4 18 [2] 83 09 [2] cd 05 [2] c1 0f [2] d6 04 [2] cd 4a [2] f0 }

  condition:
    any of them
}