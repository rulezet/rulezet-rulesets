rule TTP_XOR_MULT_DOSStub_8584 {
  strings:
    $key_8584 = { d1 ec [2] a5 f4 [2] e2 f6 [2] a5 e7 [2] eb eb [2] e7 e1 [2] f0 ea [2] eb a4 [2] d6 }

  condition:
    any of them
}