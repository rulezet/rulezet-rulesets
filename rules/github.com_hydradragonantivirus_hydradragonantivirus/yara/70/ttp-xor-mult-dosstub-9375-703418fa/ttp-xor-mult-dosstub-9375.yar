rule TTP_XOR_MULT_DOSStub_9375 {
  strings:
    $key_9375 = { c7 1d [2] b3 05 [2] f4 07 [2] b3 16 [2] fd 1a [2] f1 10 [2] e6 1b [2] fd 55 [2] c0 }

  condition:
    any of them
}