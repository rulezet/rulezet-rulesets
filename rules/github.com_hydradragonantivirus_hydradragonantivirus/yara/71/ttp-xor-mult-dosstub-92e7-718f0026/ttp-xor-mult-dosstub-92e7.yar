rule TTP_XOR_MULT_DOSStub_92e7 {
  strings:
    $key_92e7 = { c6 8f [2] b2 97 [2] f5 95 [2] b2 84 [2] fc 88 [2] f0 82 [2] e7 89 [2] fc c7 [2] c1 }

  condition:
    any of them
}