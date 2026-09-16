rule TTP_XOR_MULT_DOSStub_a757 {
  strings:
    $key_a757 = { f3 3f [2] 87 27 [2] c0 25 [2] 87 34 [2] c9 38 [2] c5 32 [2] d2 39 [2] c9 77 [2] f4 }

  condition:
    any of them
}