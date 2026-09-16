rule TTP_XOR_MULT_DOSStub_9306 {
  strings:
    $key_9306 = { c7 6e [2] b3 76 [2] f4 74 [2] b3 65 [2] fd 69 [2] f1 63 [2] e6 68 [2] fd 26 [2] c0 }

  condition:
    any of them
}