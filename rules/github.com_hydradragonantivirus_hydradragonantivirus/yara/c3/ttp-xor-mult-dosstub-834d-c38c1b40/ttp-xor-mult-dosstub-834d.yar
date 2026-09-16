rule TTP_XOR_MULT_DOSStub_834d {
  strings:
    $key_834d = { d7 25 [2] a3 3d [2] e4 3f [2] a3 2e [2] ed 22 [2] e1 28 [2] f6 23 [2] ed 6d [2] d0 }

  condition:
    any of them
}