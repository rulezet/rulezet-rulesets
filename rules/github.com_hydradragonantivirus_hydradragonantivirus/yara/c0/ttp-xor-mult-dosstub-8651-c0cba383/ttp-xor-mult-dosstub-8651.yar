rule TTP_XOR_MULT_DOSStub_8651 {
  strings:
    $key_8651 = { d2 39 [2] a6 21 [2] e1 23 [2] a6 32 [2] e8 3e [2] e4 34 [2] f3 3f [2] e8 71 [2] d5 }

  condition:
    any of them
}