rule TTP_XOR_MULT_DOSStub_9547 {
  strings:
    $key_9547 = { c1 2f [2] b5 37 [2] f2 35 [2] b5 24 [2] fb 28 [2] f7 22 [2] e0 29 [2] fb 67 [2] c6 }

  condition:
    any of them
}