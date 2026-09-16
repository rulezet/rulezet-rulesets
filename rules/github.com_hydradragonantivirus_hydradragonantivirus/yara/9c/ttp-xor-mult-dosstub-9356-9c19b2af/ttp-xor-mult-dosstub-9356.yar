rule TTP_XOR_MULT_DOSStub_9356 {
  strings:
    $key_9356 = { c7 3e [2] b3 26 [2] f4 24 [2] b3 35 [2] fd 39 [2] f1 33 [2] e6 38 [2] fd 76 [2] c0 }

  condition:
    any of them
}