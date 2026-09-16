rule TTP_XOR_MULT_DOSStub_9314 {
  strings:
    $key_9314 = { c7 7c [2] b3 64 [2] f4 66 [2] b3 77 [2] fd 7b [2] f1 71 [2] e6 7a [2] fd 34 [2] c0 }

  condition:
    any of them
}