rule TTP_XOR_MULT_DOSStub_9351 {
  strings:
    $key_9351 = { c7 39 [2] b3 21 [2] f4 23 [2] b3 32 [2] fd 3e [2] f1 34 [2] e6 3f [2] fd 71 [2] c0 }

  condition:
    any of them
}