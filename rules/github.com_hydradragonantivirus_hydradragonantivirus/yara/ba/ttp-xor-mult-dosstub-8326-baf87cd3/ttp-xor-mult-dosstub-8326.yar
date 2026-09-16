rule TTP_XOR_MULT_DOSStub_8326 {
  strings:
    $key_8326 = { d7 4e [2] a3 56 [2] e4 54 [2] a3 45 [2] ed 49 [2] e1 43 [2] f6 48 [2] ed 06 [2] d0 }

  condition:
    any of them
}