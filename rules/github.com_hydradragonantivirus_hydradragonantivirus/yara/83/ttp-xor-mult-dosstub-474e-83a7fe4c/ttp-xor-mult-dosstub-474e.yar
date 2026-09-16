rule TTP_XOR_MULT_DOSStub_474e {
  strings:
    $key_474e = { 13 26 [2] 67 3e [2] 20 3c [2] 67 2d [2] 29 21 [2] 25 2b [2] 32 20 [2] 29 6e [2] 14 }

  condition:
    any of them
}