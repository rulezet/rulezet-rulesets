rule TTP_XOR_MULT_DOSStub_a31c {
  strings:
    $key_a31c = { f7 74 [2] 83 6c [2] c4 6e [2] 83 7f [2] cd 73 [2] c1 79 [2] d6 72 [2] cd 3c [2] f0 }

  condition:
    any of them
}