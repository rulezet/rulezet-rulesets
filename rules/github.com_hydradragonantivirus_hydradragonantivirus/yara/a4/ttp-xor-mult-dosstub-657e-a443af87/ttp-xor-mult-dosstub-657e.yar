rule TTP_XOR_MULT_DOSStub_657e {
  strings:
    $key_657e = { 31 16 [2] 45 0e [2] 02 0c [2] 45 1d [2] 0b 11 [2] 07 1b [2] 10 10 [2] 0b 5e [2] 36 }

  condition:
    any of them
}