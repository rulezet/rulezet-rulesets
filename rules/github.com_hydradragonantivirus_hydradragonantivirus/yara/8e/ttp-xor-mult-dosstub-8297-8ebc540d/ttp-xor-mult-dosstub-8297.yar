rule TTP_XOR_MULT_DOSStub_8297 {
  strings:
    $key_8297 = { d6 ff [2] a2 e7 [2] e5 e5 [2] a2 f4 [2] ec f8 [2] e0 f2 [2] f7 f9 [2] ec b7 [2] d1 }

  condition:
    any of them
}