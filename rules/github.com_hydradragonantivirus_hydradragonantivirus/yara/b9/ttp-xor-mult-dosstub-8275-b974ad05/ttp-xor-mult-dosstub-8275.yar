rule TTP_XOR_MULT_DOSStub_8275 {
  strings:
    $key_8275 = { d6 1d [2] a2 05 [2] e5 07 [2] a2 16 [2] ec 1a [2] e0 10 [2] f7 1b [2] ec 55 [2] d1 }

  condition:
    any of them
}