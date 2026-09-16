rule TTP_XOR_MULT_DOSStub_9477 {
  strings:
    $key_9477 = { c0 1f [2] b4 07 [2] f3 05 [2] b4 14 [2] fa 18 [2] f6 12 [2] e1 19 [2] fa 57 [2] c7 }

  condition:
    any of them
}