rule TTP_XOR_MULT_DOSStub_9358 {
  strings:
    $key_9358 = { c7 30 [2] b3 28 [2] f4 2a [2] b3 3b [2] fd 37 [2] f1 3d [2] e6 36 [2] fd 78 [2] c0 }

  condition:
    any of them
}