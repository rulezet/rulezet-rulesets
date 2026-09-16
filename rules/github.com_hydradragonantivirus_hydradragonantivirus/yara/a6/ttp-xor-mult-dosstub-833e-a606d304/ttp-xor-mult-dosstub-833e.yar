rule TTP_XOR_MULT_DOSStub_833e {
  strings:
    $key_833e = { d7 56 [2] a3 4e [2] e4 4c [2] a3 5d [2] ed 51 [2] e1 5b [2] f6 50 [2] ed 1e [2] d0 }

  condition:
    any of them
}