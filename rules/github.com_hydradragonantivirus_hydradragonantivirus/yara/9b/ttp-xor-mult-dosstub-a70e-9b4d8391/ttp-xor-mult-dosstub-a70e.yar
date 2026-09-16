rule TTP_XOR_MULT_DOSStub_a70e {
  strings:
    $key_a70e = { f3 66 [2] 87 7e [2] c0 7c [2] 87 6d [2] c9 61 [2] c5 6b [2] d2 60 [2] c9 2e [2] f4 }

  condition:
    any of them
}