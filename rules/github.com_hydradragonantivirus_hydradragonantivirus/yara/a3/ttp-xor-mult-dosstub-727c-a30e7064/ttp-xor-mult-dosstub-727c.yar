rule TTP_XOR_MULT_DOSStub_727c {
  strings:
    $key_727c = { 26 14 [2] 52 0c [2] 15 0e [2] 52 1f [2] 1c 13 [2] 10 19 [2] 07 12 [2] 1c 5c [2] 21 }

  condition:
    any of them
}