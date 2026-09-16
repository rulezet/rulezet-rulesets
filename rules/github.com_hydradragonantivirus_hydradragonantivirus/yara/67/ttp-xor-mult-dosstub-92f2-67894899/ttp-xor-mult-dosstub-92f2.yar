rule TTP_XOR_MULT_DOSStub_92f2 {
  strings:
    $key_92f2 = { c6 9a [2] b2 82 [2] f5 80 [2] b2 91 [2] fc 9d [2] f0 97 [2] e7 9c [2] fc d2 [2] c1 }

  condition:
    any of them
}