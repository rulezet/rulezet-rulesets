rule TTP_XOR_MULT_DOSStub_543e {
  strings:
    $key_543e = { 00 56 [2] 74 4e [2] 33 4c [2] 74 5d [2] 3a 51 [2] 36 5b [2] 21 50 [2] 3a 1e [2] 07 }

  condition:
    any of them
}