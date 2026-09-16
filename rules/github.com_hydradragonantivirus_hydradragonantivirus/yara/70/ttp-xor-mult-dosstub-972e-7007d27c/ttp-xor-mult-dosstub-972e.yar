rule TTP_XOR_MULT_DOSStub_972e {
  strings:
    $key_972e = { c3 46 [2] b7 5e [2] f0 5c [2] b7 4d [2] f9 41 [2] f5 4b [2] e2 40 [2] f9 0e [2] c4 }

  condition:
    any of them
}