rule TTP_XOR_MULT_DOSStub_9363 {
  strings:
    $key_9363 = { c7 0b [2] b3 13 [2] f4 11 [2] b3 00 [2] fd 0c [2] f1 06 [2] e6 0d [2] fd 43 [2] c0 }

  condition:
    any of them
}