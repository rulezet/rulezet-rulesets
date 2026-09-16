rule TTP_XOR_MULT_DOSStub_9470 {
  strings:
    $key_9470 = { c0 18 [2] b4 00 [2] f3 02 [2] b4 13 [2] fa 1f [2] f6 15 [2] e1 1e [2] fa 50 [2] c7 }

  condition:
    any of them
}