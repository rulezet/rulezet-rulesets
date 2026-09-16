rule TTP_XOR_MULT_DOSStub_9349 {
  strings:
    $key_9349 = { c7 21 [2] b3 39 [2] f4 3b [2] b3 2a [2] fd 26 [2] f1 2c [2] e6 27 [2] fd 69 [2] c0 }

  condition:
    any of them
}