rule TTP_XOR_MULT_DOSStub_834e {
  strings:
    $key_834e = { d7 26 [2] a3 3e [2] e4 3c [2] a3 2d [2] ed 21 [2] e1 2b [2] f6 20 [2] ed 6e [2] d0 }

  condition:
    any of them
}