rule TTP_XOR_MULT_DOSStub_934a {
  strings:
    $key_934a = { c7 22 [2] b3 3a [2] f4 38 [2] b3 29 [2] fd 25 [2] f1 2f [2] e6 24 [2] fd 6a [2] c0 }

  condition:
    any of them
}