rule TTP_XOR_MULT_DOSStub_9445 {
  strings:
    $key_9445 = { c0 2d [2] b4 35 [2] f3 37 [2] b4 26 [2] fa 2a [2] f6 20 [2] e1 2b [2] fa 65 [2] c7 }

  condition:
    any of them
}