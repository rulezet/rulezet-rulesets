rule TTP_XOR_MULT_DOSStub_9730 {
  strings:
    $key_9730 = { c3 58 [2] b7 40 [2] f0 42 [2] b7 53 [2] f9 5f [2] f5 55 [2] e2 5e [2] f9 10 [2] c4 }

  condition:
    any of them
}