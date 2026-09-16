rule TTP_XOR_MULT_DOSStub_472e {
  strings:
    $key_472e = { 13 46 [2] 67 5e [2] 20 5c [2] 67 4d [2] 29 41 [2] 25 4b [2] 32 40 [2] 29 0e [2] 14 }

  condition:
    any of them
}