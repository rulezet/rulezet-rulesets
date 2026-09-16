rule TTP_XOR_MULT_DOSStub_9447 {
  strings:
    $key_9447 = { c0 2f [2] b4 37 [2] f3 35 [2] b4 24 [2] fa 28 [2] f6 22 [2] e1 29 [2] fa 67 [2] c7 }

  condition:
    any of them
}