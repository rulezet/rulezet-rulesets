rule TTP_XOR_MULT_DOSStub_9427 {
  strings:
    $key_9427 = { c0 4f [2] b4 57 [2] f3 55 [2] b4 44 [2] fa 48 [2] f6 42 [2] e1 49 [2] fa 07 [2] c7 }

  condition:
    any of them
}