rule TTP_XOR_MULT_DOSStub_977c {
  strings:
    $key_977c = { c3 14 [2] b7 0c [2] f0 0e [2] b7 1f [2] f9 13 [2] f5 19 [2] e2 12 [2] f9 5c [2] c4 }

  condition:
    any of them
}