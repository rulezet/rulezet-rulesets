rule TTP_XOR_MULT_DOSStub_9347 {
  strings:
    $key_9347 = { c7 2f [2] b3 37 [2] f4 35 [2] b3 24 [2] fd 28 [2] f1 22 [2] e6 29 [2] fd 67 [2] c0 }

  condition:
    any of them
}