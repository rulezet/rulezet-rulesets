rule TTP_XOR_MULT_DOSStub_832e {
  strings:
    $key_832e = { d7 46 [2] a3 5e [2] e4 5c [2] a3 4d [2] ed 41 [2] e1 4b [2] f6 40 [2] ed 0e [2] d0 }

  condition:
    any of them
}