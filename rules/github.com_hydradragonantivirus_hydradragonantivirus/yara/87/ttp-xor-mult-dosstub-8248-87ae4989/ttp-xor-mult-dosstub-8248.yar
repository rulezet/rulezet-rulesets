rule TTP_XOR_MULT_DOSStub_8248 {
  strings:
    $key_8248 = { d6 20 [2] a2 38 [2] e5 3a [2] a2 2b [2] ec 27 [2] e0 2d [2] f7 26 [2] ec 68 [2] d1 }

  condition:
    any of them
}