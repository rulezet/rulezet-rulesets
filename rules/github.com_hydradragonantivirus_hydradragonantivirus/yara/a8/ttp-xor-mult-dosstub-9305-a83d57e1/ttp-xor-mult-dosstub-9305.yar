rule TTP_XOR_MULT_DOSStub_9305 {
  strings:
    $key_9305 = { c7 6d [2] b3 75 [2] f4 77 [2] b3 66 [2] fd 6a [2] f1 60 [2] e6 6b [2] fd 25 [2] c0 }

  condition:
    any of them
}