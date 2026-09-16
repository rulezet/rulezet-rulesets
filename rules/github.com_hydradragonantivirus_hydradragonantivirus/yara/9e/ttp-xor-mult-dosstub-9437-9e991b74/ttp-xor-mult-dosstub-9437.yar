rule TTP_XOR_MULT_DOSStub_9437 {
  strings:
    $key_9437 = { c0 5f [2] b4 47 [2] f3 45 [2] b4 54 [2] fa 58 [2] f6 52 [2] e1 59 [2] fa 17 [2] c7 }

  condition:
    any of them
}