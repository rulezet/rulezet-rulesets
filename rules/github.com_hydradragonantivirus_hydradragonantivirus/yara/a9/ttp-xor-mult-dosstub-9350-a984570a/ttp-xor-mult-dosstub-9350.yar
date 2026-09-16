rule TTP_XOR_MULT_DOSStub_9350 {
  strings:
    $key_9350 = { c7 38 [2] b3 20 [2] f4 22 [2] b3 33 [2] fd 3f [2] f1 35 [2] e6 3e [2] fd 70 [2] c0 }

  condition:
    any of them
}