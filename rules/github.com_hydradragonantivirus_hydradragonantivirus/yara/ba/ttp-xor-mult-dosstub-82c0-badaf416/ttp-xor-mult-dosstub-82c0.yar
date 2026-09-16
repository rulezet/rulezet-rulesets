rule TTP_XOR_MULT_DOSStub_82c0 {
  strings:
    $key_82c0 = { d6 a8 [2] a2 b0 [2] e5 b2 [2] a2 a3 [2] ec af [2] e0 a5 [2] f7 ae [2] ec e0 [2] d1 }

  condition:
    any of them
}