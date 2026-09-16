rule TTP_XOR_MULT_DOSStub_8258 {
  strings:
    $key_8258 = { d6 30 [2] a2 28 [2] e5 2a [2] a2 3b [2] ec 37 [2] e0 3d [2] f7 36 [2] ec 78 [2] d1 }

  condition:
    any of them
}