rule TTP_XOR_MULT_DOSStub_9737 {
  strings:
    $key_9737 = { c3 5f [2] b7 47 [2] f0 45 [2] b7 54 [2] f9 58 [2] f5 52 [2] e2 59 [2] f9 17 [2] c4 }

  condition:
    any of them
}