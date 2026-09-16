rule TTP_XOR_MULT_DOSStub_827e {
  strings:
    $key_827e = { d6 16 [2] a2 0e [2] e5 0c [2] a2 1d [2] ec 11 [2] e0 1b [2] f7 10 [2] ec 5e [2] d1 }

  condition:
    any of them
}