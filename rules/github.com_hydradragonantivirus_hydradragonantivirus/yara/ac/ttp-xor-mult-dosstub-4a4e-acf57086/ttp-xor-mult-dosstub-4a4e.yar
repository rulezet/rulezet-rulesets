rule TTP_XOR_MULT_DOSStub_4a4e {
  strings:
    $key_4a4e = { 1e 26 [2] 6a 3e [2] 2d 3c [2] 6a 2d [2] 24 21 [2] 28 2b [2] 3f 20 [2] 24 6e [2] 19 }

  condition:
    any of them
}