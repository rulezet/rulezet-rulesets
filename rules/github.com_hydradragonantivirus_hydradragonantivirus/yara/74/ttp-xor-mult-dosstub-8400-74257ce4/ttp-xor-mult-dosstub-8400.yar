rule TTP_XOR_MULT_DOSStub_8400 {
  strings:
    $key_8400 = { d0 68 [2] a4 70 [2] e3 72 [2] a4 63 [2] ea 6f [2] e6 65 [2] f1 6e [2] ea 20 [2] d7 }

  condition:
    any of them
}