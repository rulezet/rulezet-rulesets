rule TTP_XOR_MULT_DOSStub_404e {
  strings:
    $key_404e = { 14 26 [2] 60 3e [2] 27 3c [2] 60 2d [2] 2e 21 [2] 22 2b [2] 35 20 [2] 2e 6e [2] 13 }

  condition:
    any of them
}