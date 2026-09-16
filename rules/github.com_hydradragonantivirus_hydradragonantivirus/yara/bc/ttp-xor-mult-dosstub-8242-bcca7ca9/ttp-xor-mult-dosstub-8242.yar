rule TTP_XOR_MULT_DOSStub_8242 {
  strings:
    $key_8242 = { d6 2a [2] a2 32 [2] e5 30 [2] a2 21 [2] ec 2d [2] e0 27 [2] f7 2c [2] ec 62 [2] d1 }

  condition:
    any of them
}