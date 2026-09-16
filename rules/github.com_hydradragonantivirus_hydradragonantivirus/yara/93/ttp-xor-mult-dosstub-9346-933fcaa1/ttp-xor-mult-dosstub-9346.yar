rule TTP_XOR_MULT_DOSStub_9346 {
  strings:
    $key_9346 = { c7 2e [2] b3 36 [2] f4 34 [2] b3 25 [2] fd 29 [2] f1 23 [2] e6 28 [2] fd 66 [2] c0 }

  condition:
    any of them
}