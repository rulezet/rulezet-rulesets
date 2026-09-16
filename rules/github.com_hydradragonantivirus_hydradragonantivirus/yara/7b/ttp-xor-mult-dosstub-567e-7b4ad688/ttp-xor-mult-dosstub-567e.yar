rule TTP_XOR_MULT_DOSStub_567e {
  strings:
    $key_567e = { 02 16 [2] 76 0e [2] 31 0c [2] 76 1d [2] 38 11 [2] 34 1b [2] 23 10 [2] 38 5e [2] 05 }

  condition:
    any of them
}