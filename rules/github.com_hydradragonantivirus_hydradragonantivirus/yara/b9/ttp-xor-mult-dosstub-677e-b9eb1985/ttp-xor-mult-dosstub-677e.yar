rule TTP_XOR_MULT_DOSStub_677e {
  strings:
    $key_677e = { 33 16 [2] 47 0e [2] 00 0c [2] 47 1d [2] 09 11 [2] 05 1b [2] 12 10 [2] 09 5e [2] 34 }

  condition:
    any of them
}