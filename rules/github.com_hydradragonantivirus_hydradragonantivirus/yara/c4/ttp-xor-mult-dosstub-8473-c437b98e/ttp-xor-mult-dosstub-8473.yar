rule TTP_XOR_MULT_DOSStub_8473 {
  strings:
    $key_8473 = { d0 1b [2] a4 03 [2] e3 01 [2] a4 10 [2] ea 1c [2] e6 16 [2] f1 1d [2] ea 53 [2] d7 }

  condition:
    any of them
}