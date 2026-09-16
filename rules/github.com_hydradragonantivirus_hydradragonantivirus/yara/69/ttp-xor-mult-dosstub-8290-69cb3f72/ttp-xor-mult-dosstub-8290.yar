rule TTP_XOR_MULT_DOSStub_8290 {
  strings:
    $key_8290 = { d6 f8 [2] a2 e0 [2] e5 e2 [2] a2 f3 [2] ec ff [2] e0 f5 [2] f7 fe [2] ec b0 [2] d1 }

  condition:
    any of them
}