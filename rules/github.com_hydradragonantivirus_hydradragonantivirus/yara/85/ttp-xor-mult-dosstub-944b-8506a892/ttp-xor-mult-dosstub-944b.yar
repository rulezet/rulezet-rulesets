rule TTP_XOR_MULT_DOSStub_944b {
  strings:
    $key_944b = { c0 23 [2] b4 3b [2] f3 39 [2] b4 28 [2] fa 24 [2] f6 2e [2] e1 25 [2] fa 6b [2] c7 }

  condition:
    any of them
}