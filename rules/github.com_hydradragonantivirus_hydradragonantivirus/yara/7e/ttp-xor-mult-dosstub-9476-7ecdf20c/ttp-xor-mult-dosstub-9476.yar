rule TTP_XOR_MULT_DOSStub_9476 {
  strings:
    $key_9476 = { c0 1e [2] b4 06 [2] f3 04 [2] b4 15 [2] fa 19 [2] f6 13 [2] e1 18 [2] fa 56 [2] c7 }

  condition:
    any of them
}