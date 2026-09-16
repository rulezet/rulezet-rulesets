rule TTP_XOR_MULT_DOSStub_851e {
  strings:
    $key_851e = { d1 76 [2] a5 6e [2] e2 6c [2] a5 7d [2] eb 71 [2] e7 7b [2] f0 70 [2] eb 3e [2] d6 }

  condition:
    any of them
}