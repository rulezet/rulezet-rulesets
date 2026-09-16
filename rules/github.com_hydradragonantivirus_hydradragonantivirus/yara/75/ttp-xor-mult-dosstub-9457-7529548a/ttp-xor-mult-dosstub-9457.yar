rule TTP_XOR_MULT_DOSStub_9457 {
  strings:
    $key_9457 = { c0 3f [2] b4 27 [2] f3 25 [2] b4 34 [2] fa 38 [2] f6 32 [2] e1 39 [2] fa 77 [2] c7 }

  condition:
    any of them
}