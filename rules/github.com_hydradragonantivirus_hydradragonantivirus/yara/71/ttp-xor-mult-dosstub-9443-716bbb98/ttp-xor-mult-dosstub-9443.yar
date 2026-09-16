rule TTP_XOR_MULT_DOSStub_9443 {
  strings:
    $key_9443 = { c0 2b [2] b4 33 [2] f3 31 [2] b4 20 [2] fa 2c [2] f6 26 [2] e1 2d [2] fa 63 [2] c7 }

  condition:
    any of them
}