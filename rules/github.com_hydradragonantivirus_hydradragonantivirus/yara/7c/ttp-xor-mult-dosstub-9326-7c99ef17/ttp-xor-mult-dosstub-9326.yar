rule TTP_XOR_MULT_DOSStub_9326 {
  strings:
    $key_9326 = { c7 4e [2] b3 56 [2] f4 54 [2] b3 45 [2] fd 49 [2] f1 43 [2] e6 48 [2] fd 06 [2] c0 }

  condition:
    any of them
}