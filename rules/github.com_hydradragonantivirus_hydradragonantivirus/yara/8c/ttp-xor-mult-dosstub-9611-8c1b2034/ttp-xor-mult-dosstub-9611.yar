rule TTP_XOR_MULT_DOSStub_9611 {
  strings:
    $key_9611 = { c2 79 [2] b6 61 [2] f1 63 [2] b6 72 [2] f8 7e [2] f4 74 [2] e3 7f [2] f8 31 [2] c5 }

  condition:
    any of them
}