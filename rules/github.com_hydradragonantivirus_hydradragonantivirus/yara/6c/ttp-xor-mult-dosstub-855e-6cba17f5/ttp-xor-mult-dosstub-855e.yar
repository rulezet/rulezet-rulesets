rule TTP_XOR_MULT_DOSStub_855e {
  strings:
    $key_855e = { d1 36 [2] a5 2e [2] e2 2c [2] a5 3d [2] eb 31 [2] e7 3b [2] f0 30 [2] eb 7e [2] d6 }

  condition:
    any of them
}