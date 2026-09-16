rule TTP_XOR_MULT_DOSStub_767e {
  strings:
    $key_767e = { 22 16 [2] 56 0e [2] 11 0c [2] 56 1d [2] 18 11 [2] 14 1b [2] 03 10 [2] 18 5e [2] 25 }

  condition:
    any of them
}