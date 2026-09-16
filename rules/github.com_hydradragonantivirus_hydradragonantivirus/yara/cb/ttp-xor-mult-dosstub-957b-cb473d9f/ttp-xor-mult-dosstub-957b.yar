rule TTP_XOR_MULT_DOSStub_957b {
  strings:
    $key_957b = { c1 13 [2] b5 0b [2] f2 09 [2] b5 18 [2] fb 14 [2] f7 1e [2] e0 15 [2] fb 5b [2] c6 }

  condition:
    any of them
}