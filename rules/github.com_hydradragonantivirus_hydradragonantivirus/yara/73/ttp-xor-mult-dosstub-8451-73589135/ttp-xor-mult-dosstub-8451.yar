rule TTP_XOR_MULT_DOSStub_8451 {
  strings:
    $key_8451 = { d0 39 [2] a4 21 [2] e3 23 [2] a4 32 [2] ea 3e [2] e6 34 [2] f1 3f [2] ea 71 [2] d7 }

  condition:
    any of them
}