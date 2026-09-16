rule TTP_XOR_MULT_DOSStub_977b {
  strings:
    $key_977b = { c3 13 [2] b7 0b [2] f0 09 [2] b7 18 [2] f9 14 [2] f5 1e [2] e2 15 [2] f9 5b [2] c4 }

  condition:
    any of them
}