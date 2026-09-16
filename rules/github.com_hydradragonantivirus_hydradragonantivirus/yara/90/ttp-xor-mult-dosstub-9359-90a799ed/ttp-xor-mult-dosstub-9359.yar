rule TTP_XOR_MULT_DOSStub_9359 {
  strings:
    $key_9359 = { c7 31 [2] b3 29 [2] f4 2b [2] b3 3a [2] fd 36 [2] f1 3c [2] e6 37 [2] fd 79 [2] c0 }

  condition:
    any of them
}