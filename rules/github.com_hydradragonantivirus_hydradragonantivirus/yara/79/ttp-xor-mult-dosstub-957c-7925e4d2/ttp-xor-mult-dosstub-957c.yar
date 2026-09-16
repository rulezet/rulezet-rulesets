rule TTP_XOR_MULT_DOSStub_957c {
  strings:
    $key_957c = { c1 14 [2] b5 0c [2] f2 0e [2] b5 1f [2] fb 13 [2] f7 19 [2] e0 12 [2] fb 5c [2] c6 }

  condition:
    any of them
}