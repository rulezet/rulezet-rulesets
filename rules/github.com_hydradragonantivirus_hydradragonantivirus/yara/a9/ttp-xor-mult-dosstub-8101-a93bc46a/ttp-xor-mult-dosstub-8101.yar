rule TTP_XOR_MULT_DOSStub_8101 {
  strings:
    $key_8101 = { d5 69 [2] a1 71 [2] e6 73 [2] a1 62 [2] ef 6e [2] e3 64 [2] f4 6f [2] ef 21 [2] d2 }

  condition:
    any of them
}