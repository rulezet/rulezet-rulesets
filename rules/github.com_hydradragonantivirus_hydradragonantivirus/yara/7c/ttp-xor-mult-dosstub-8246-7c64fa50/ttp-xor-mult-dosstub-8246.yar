rule TTP_XOR_MULT_DOSStub_8246 {
  strings:
    $key_8246 = { d6 2e [2] a2 36 [2] e5 34 [2] a2 25 [2] ec 29 [2] e0 23 [2] f7 28 [2] ec 66 [2] d1 }

  condition:
    any of them
}