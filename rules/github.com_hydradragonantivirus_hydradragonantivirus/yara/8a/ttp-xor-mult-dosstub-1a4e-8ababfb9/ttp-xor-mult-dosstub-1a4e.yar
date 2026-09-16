rule TTP_XOR_MULT_DOSStub_1a4e {
  strings:
    $key_1a4e = { 4e 26 [2] 3a 3e [2] 7d 3c [2] 3a 2d [2] 74 21 [2] 78 2b [2] 6f 20 [2] 74 6e [2] 49 }

  condition:
    any of them
}