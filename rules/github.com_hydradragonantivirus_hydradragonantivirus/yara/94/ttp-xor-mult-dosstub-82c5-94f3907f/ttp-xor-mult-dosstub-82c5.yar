rule TTP_XOR_MULT_DOSStub_82c5 {
  strings:
    $key_82c5 = { d6 ad [2] a2 b5 [2] e5 b7 [2] a2 a6 [2] ec aa [2] e0 a0 [2] f7 ab [2] ec e5 [2] d1 }

  condition:
    any of them
}