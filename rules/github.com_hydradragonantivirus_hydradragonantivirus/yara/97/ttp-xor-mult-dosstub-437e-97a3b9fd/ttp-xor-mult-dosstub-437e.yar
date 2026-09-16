rule TTP_XOR_MULT_DOSStub_437e {
  strings:
    $key_437e = { 17 16 [2] 63 0e [2] 24 0c [2] 63 1d [2] 2d 11 [2] 21 1b [2] 36 10 [2] 2d 5e [2] 10 }

  condition:
    any of them
}