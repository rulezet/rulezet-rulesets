rule TTP_XOR_MULT_DOSStub_9610 {
  strings:
    $key_9610 = { c2 78 [2] b6 60 [2] f1 62 [2] b6 73 [2] f8 7f [2] f4 75 [2] e3 7e [2] f8 30 [2] c5 }

  condition:
    any of them
}