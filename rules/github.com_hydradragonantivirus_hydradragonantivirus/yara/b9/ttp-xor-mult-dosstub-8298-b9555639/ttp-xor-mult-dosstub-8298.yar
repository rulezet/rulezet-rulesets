rule TTP_XOR_MULT_DOSStub_8298 {
  strings:
    $key_8298 = { d6 f0 [2] a2 e8 [2] e5 ea [2] a2 fb [2] ec f7 [2] e0 fd [2] f7 f6 [2] ec b8 [2] d1 }

  condition:
    any of them
}