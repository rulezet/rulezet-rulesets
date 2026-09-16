rule TTP_XOR_MULT_DOSStub_8479 {
  strings:
    $key_8479 = { d0 11 [2] a4 09 [2] e3 0b [2] a4 1a [2] ea 16 [2] e6 1c [2] f1 17 [2] ea 59 [2] d7 }

  condition:
    any of them
}