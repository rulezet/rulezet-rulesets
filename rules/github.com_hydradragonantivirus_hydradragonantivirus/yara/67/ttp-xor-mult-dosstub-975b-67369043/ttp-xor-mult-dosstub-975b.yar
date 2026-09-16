rule TTP_XOR_MULT_DOSStub_975b {
  strings:
    $key_975b = { c3 33 [2] b7 2b [2] f0 29 [2] b7 38 [2] f9 34 [2] f5 3e [2] e2 35 [2] f9 7b [2] c4 }

  condition:
    any of them
}