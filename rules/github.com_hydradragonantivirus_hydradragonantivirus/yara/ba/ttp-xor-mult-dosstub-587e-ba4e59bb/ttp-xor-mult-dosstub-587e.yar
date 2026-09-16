rule TTP_XOR_MULT_DOSStub_587e {
  strings:
    $key_587e = { 0c 16 [2] 78 0e [2] 3f 0c [2] 78 1d [2] 36 11 [2] 3a 1b [2] 2d 10 [2] 36 5e [2] 0b }

  condition:
    any of them
}