rule TTP_XOR_MULT_DOSStub_4a7e {
  strings:
    $key_4a7e = { 1e 16 [2] 6a 0e [2] 2d 0c [2] 6a 1d [2] 24 11 [2] 28 1b [2] 3f 10 [2] 24 5e [2] 19 }

  condition:
    any of them
}