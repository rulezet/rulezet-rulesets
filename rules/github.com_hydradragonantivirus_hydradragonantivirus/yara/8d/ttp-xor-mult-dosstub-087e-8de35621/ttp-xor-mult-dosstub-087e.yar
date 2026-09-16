rule TTP_XOR_MULT_DOSStub_087e {
  strings:
    $key_087e = { 5c 16 [2] 28 0e [2] 6f 0c [2] 28 1d [2] 66 11 [2] 6a 1b [2] 7d 10 [2] 66 5e [2] 5b }

  condition:
    any of them
}