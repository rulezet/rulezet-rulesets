rule TTP_XOR_MULT_DOSStub_9377 {
  strings:
    $key_9377 = { c7 1f [2] b3 07 [2] f4 05 [2] b3 14 [2] fd 18 [2] f1 12 [2] e6 19 [2] fd 57 [2] c0 }

  condition:
    any of them
}