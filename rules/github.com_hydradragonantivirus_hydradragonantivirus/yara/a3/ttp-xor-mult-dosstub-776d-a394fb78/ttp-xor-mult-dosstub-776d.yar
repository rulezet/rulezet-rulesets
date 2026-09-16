rule TTP_XOR_MULT_DOSStub_776d {
  strings:
    $key_776d = { 23 05 [2] 57 1d [2] 10 1f [2] 57 0e [2] 19 02 [2] 15 08 [2] 02 03 [2] 19 4d [2] 24 }

  condition:
    any of them
}