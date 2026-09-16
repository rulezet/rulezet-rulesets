rule TTP_XOR_MULT_DOSStub_975e {
  strings:
    $key_975e = { c3 36 [2] b7 2e [2] f0 2c [2] b7 3d [2] f9 31 [2] f5 3b [2] e2 30 [2] f9 7e [2] c4 }

  condition:
    any of them
}