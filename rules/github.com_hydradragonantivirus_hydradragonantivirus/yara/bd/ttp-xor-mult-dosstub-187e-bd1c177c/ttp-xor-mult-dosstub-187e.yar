rule TTP_XOR_MULT_DOSStub_187e {
  strings:
    $key_187e = { 4c 16 [2] 38 0e [2] 7f 0c [2] 38 1d [2] 76 11 [2] 7a 1b [2] 6d 10 [2] 76 5e [2] 4b }

  condition:
    any of them
}