rule TTP_XOR_MULT_DOSStub_274e {
  strings:
    $key_274e = { 73 26 [2] 07 3e [2] 40 3c [2] 07 2d [2] 49 21 [2] 45 2b [2] 52 20 [2] 49 6e [2] 74 }

  condition:
    any of them
}