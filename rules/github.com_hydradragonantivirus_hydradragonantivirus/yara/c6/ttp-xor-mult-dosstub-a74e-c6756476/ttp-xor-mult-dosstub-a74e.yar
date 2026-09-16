rule TTP_XOR_MULT_DOSStub_a74e {
  strings:
    $key_a74e = { f3 26 [2] 87 3e [2] c0 3c [2] 87 2d [2] c9 21 [2] c5 2b [2] d2 20 [2] c9 6e [2] f4 }

  condition:
    any of them
}