rule TTP_XOR_MULT_DOSStub_9473 {
  strings:
    $key_9473 = { c0 1b [2] b4 03 [2] f3 01 [2] b4 10 [2] fa 1c [2] f6 16 [2] e1 1d [2] fa 53 [2] c7 }

  condition:
    any of them
}