rule TTP_XOR_MULT_DOSStub_544e {
  strings:
    $key_544e = { 00 26 [2] 74 3e [2] 33 3c [2] 74 2d [2] 3a 21 [2] 36 2b [2] 21 20 [2] 3a 6e [2] 07 }

  condition:
    any of them
}