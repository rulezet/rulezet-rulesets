rule TTP_XOR_MULT_DOSStub_537e {
  strings:
    $key_537e = { 07 16 [2] 73 0e [2] 34 0c [2] 73 1d [2] 3d 11 [2] 31 1b [2] 26 10 [2] 3d 5e [2] 00 }

  condition:
    any of them
}