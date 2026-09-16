rule TTP_XOR_MULT_DOSStub_9484 {
  strings:
    $key_9484 = { c0 ec [2] b4 f4 [2] f3 f6 [2] b4 e7 [2] fa eb [2] f6 e1 [2] e1 ea [2] fa a4 [2] c7 }

  condition:
    any of them
}