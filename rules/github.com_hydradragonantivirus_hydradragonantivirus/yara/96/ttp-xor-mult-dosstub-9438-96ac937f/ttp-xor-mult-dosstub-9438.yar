rule TTP_XOR_MULT_DOSStub_9438 {
  strings:
    $key_9438 = { c0 50 [2] b4 48 [2] f3 4a [2] b4 5b [2] fa 57 [2] f6 5d [2] e1 56 [2] fa 18 [2] c7 }

  condition:
    any of them
}