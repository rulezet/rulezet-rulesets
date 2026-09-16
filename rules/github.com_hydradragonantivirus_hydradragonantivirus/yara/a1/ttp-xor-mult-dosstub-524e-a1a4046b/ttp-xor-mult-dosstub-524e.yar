rule TTP_XOR_MULT_DOSStub_524e {
  strings:
    $key_524e = { 06 26 [2] 72 3e [2] 35 3c [2] 72 2d [2] 3c 21 [2] 30 2b [2] 27 20 [2] 3c 6e [2] 01 }

  condition:
    any of them
}