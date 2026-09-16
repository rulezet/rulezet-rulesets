rule TTP_XOR_MULT_DOSStub_9227 {
  strings:
    $key_9227 = { c6 4f [2] b2 57 [2] f5 55 [2] b2 44 [2] fc 48 [2] f0 42 [2] e7 49 [2] fc 07 [2] c1 }

  condition:
    any of them
}