rule TTP_XOR_MULT_DOSStub_857e {
  strings:
    $key_857e = { d1 16 [2] a5 0e [2] e2 0c [2] a5 1d [2] eb 11 [2] e7 1b [2] f0 10 [2] eb 5e [2] d6 }

  condition:
    any of them
}