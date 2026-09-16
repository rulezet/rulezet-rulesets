rule TTP_XOR_MULT_DOSStub_934b {
  strings:
    $key_934b = { c7 23 [2] b3 3b [2] f4 39 [2] b3 28 [2] fd 24 [2] f1 2e [2] e6 25 [2] fd 6b [2] c0 }

  condition:
    any of them
}