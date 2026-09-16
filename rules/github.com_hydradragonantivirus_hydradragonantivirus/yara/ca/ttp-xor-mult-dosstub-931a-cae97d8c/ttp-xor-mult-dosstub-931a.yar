rule TTP_XOR_MULT_DOSStub_931a {
  strings:
    $key_931a = { c7 72 [2] b3 6a [2] f4 68 [2] b3 79 [2] fd 75 [2] f1 7f [2] e6 74 [2] fd 3a [2] c0 }

  condition:
    any of them
}