rule TTP_XOR_MULT_DOSStub_9352 {
  strings:
    $key_9352 = { c7 3a [2] b3 22 [2] f4 20 [2] b3 31 [2] fd 3d [2] f1 37 [2] e6 3c [2] fd 72 [2] c0 }

  condition:
    any of them
}