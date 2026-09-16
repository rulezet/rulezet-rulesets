rule TTP_XOR_MULT_DOSStub_9440 {
  strings:
    $key_9440 = { c0 28 [2] b4 30 [2] f3 32 [2] b4 23 [2] fa 2f [2] f6 25 [2] e1 2e [2] fa 60 [2] c7 }

  condition:
    any of them
}