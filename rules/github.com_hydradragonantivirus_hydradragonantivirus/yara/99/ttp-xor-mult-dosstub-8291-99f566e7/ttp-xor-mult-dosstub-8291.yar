rule TTP_XOR_MULT_DOSStub_8291 {
  strings:
    $key_8291 = { d6 f9 [2] a2 e1 [2] e5 e3 [2] a2 f2 [2] ec fe [2] e0 f4 [2] f7 ff [2] ec b1 [2] d1 }

  condition:
    any of them
}