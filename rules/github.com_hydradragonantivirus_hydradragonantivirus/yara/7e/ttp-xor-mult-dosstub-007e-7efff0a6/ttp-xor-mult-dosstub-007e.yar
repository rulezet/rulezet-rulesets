rule TTP_XOR_MULT_DOSStub_007e {
  strings:
    $key_007e = { 54 16 [2] 20 0e [2] 67 0c [2] 20 1d [2] 6e 11 [2] 62 1b [2] 75 10 [2] 6e 5e [2] 53 }

  condition:
    any of them
}