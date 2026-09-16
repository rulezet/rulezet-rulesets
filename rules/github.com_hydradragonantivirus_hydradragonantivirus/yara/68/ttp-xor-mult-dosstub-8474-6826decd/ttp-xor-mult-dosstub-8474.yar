rule TTP_XOR_MULT_DOSStub_8474 {
  strings:
    $key_8474 = { d0 1c [2] a4 04 [2] e3 06 [2] a4 17 [2] ea 1b [2] e6 11 [2] f1 1a [2] ea 54 [2] d7 }

  condition:
    any of them
}