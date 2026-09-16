rule TTP_XOR_MULT_DOSStub_8413 {
  strings:
    $key_8413 = { d0 7b [2] a4 63 [2] e3 61 [2] a4 70 [2] ea 7c [2] e6 76 [2] f1 7d [2] ea 33 [2] d7 }

  condition:
    any of them
}