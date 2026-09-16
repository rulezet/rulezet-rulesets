rule TTP_XOR_MULT_DOSStub_9318 {
  strings:
    $key_9318 = { c7 70 [2] b3 68 [2] f4 6a [2] b3 7b [2] fd 77 [2] f1 7d [2] e6 76 [2] fd 38 [2] c0 }

  condition:
    any of them
}