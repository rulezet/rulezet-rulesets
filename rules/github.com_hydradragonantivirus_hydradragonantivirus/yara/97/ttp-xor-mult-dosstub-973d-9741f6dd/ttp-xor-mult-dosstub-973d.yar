rule TTP_XOR_MULT_DOSStub_973d {
  strings:
    $key_973d = { c3 55 [2] b7 4d [2] f0 4f [2] b7 5e [2] f9 52 [2] f5 58 [2] e2 53 [2] f9 1d [2] c4 }

  condition:
    any of them
}