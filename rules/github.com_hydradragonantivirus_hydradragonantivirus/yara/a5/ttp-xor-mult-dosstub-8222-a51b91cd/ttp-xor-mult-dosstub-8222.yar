rule TTP_XOR_MULT_DOSStub_8222 {
  strings:
    $key_8222 = { d6 4a [2] a2 52 [2] e5 50 [2] a2 41 [2] ec 4d [2] e0 47 [2] f7 4c [2] ec 02 [2] d1 }

  condition:
    any of them
}