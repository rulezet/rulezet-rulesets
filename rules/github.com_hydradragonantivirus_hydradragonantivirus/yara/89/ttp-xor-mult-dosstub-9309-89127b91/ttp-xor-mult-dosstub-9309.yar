rule TTP_XOR_MULT_DOSStub_9309 {
  strings:
    $key_9309 = { c7 61 [2] b3 79 [2] f4 7b [2] b3 6a [2] fd 66 [2] f1 6c [2] e6 67 [2] fd 29 [2] c0 }

  condition:
    any of them
}