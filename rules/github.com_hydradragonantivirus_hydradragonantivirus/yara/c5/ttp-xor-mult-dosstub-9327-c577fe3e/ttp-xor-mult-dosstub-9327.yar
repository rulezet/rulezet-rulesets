rule TTP_XOR_MULT_DOSStub_9327 {
  strings:
    $key_9327 = { c7 4f [2] b3 57 [2] f4 55 [2] b3 44 [2] fd 48 [2] f1 42 [2] e6 49 [2] fd 07 [2] c0 }

  condition:
    any of them
}