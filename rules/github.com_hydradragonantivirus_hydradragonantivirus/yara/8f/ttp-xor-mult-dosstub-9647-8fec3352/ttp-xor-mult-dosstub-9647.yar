rule TTP_XOR_MULT_DOSStub_9647 {
  strings:
    $key_9647 = { c2 2f [2] b6 37 [2] f1 35 [2] b6 24 [2] f8 28 [2] f4 22 [2] e3 29 [2] f8 67 [2] c5 }

  condition:
    any of them
}