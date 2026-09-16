rule TTP_XOR_MULT_DOSStub_8449 {
  strings:
    $key_8449 = { d0 21 [2] a4 39 [2] e3 3b [2] a4 2a [2] ea 26 [2] e6 2c [2] f1 27 [2] ea 69 [2] d7 }

  condition:
    any of them
}