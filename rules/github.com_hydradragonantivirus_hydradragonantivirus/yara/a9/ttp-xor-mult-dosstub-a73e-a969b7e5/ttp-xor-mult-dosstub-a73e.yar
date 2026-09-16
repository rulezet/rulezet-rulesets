rule TTP_XOR_MULT_DOSStub_a73e {
  strings:
    $key_a73e = { f3 56 [2] 87 4e [2] c0 4c [2] 87 5d [2] c9 51 [2] c5 5b [2] d2 50 [2] c9 1e [2] f4 }

  condition:
    any of them
}