rule TTP_XOR_MULT_DOSStub_973b {
  strings:
    $key_973b = { c3 53 [2] b7 4b [2] f0 49 [2] b7 58 [2] f9 54 [2] f5 5e [2] e2 55 [2] f9 1b [2] c4 }

  condition:
    any of them
}