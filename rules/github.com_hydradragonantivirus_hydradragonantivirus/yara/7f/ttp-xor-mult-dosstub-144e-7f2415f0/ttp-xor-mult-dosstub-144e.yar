rule TTP_XOR_MULT_DOSStub_144e {
  strings:
    $key_144e = { 40 26 [2] 34 3e [2] 73 3c [2] 34 2d [2] 7a 21 [2] 76 2b [2] 61 20 [2] 7a 6e [2] 47 }

  condition:
    any of them
}