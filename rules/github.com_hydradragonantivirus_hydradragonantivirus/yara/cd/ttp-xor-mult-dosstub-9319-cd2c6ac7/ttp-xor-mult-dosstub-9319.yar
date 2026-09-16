rule TTP_XOR_MULT_DOSStub_9319 {
  strings:
    $key_9319 = { c7 71 [2] b3 69 [2] f4 6b [2] b3 7a [2] fd 76 [2] f1 7c [2] e6 77 [2] fd 39 [2] c0 }

  condition:
    any of them
}