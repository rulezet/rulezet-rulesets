rule TTP_XOR_MULT_DOSStub_954d {
  strings:
    $key_954d = { c1 25 [2] b5 3d [2] f2 3f [2] b5 2e [2] fb 22 [2] f7 28 [2] e0 23 [2] fb 6d [2] c6 }

  condition:
    any of them
}