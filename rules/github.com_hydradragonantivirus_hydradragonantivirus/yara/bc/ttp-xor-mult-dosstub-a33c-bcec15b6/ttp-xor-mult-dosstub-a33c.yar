rule TTP_XOR_MULT_DOSStub_a33c {
  strings:
    $key_a33c = { f7 54 [2] 83 4c [2] c4 4e [2] 83 5f [2] cd 53 [2] c1 59 [2] d6 52 [2] cd 1c [2] f0 }

  condition:
    any of them
}