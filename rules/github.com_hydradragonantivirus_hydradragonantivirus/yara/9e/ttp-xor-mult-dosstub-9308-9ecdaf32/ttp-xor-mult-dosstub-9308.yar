rule TTP_XOR_MULT_DOSStub_9308 {
  strings:
    $key_9308 = { c7 60 [2] b3 78 [2] f4 7a [2] b3 6b [2] fd 67 [2] f1 6d [2] e6 66 [2] fd 28 [2] c0 }

  condition:
    any of them
}