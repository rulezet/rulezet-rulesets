rule TTP_XOR_MULT_DOSStub_8643 {
  strings:
    $key_8643 = { d2 2b [2] a6 33 [2] e1 31 [2] a6 20 [2] e8 2c [2] e4 26 [2] f3 2d [2] e8 63 [2] d5 }

  condition:
    any of them
}