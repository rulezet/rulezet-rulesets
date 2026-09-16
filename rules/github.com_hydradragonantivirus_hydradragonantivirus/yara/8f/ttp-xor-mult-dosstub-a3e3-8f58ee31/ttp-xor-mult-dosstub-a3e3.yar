rule TTP_XOR_MULT_DOSStub_a3e3 {
  strings:
    $key_a3e3 = { f7 8b [2] 83 93 [2] c4 91 [2] 83 80 [2] cd 8c [2] c1 86 [2] d6 8d [2] cd c3 [2] f0 }

  condition:
    any of them
}