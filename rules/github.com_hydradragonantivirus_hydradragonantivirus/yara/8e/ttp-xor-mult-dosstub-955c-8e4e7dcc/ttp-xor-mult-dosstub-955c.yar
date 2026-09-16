rule TTP_XOR_MULT_DOSStub_955c {
  strings:
    $key_955c = { c1 34 [2] b5 2c [2] f2 2e [2] b5 3f [2] fb 33 [2] f7 39 [2] e0 32 [2] fb 7c [2] c6 }

  condition:
    any of them
}