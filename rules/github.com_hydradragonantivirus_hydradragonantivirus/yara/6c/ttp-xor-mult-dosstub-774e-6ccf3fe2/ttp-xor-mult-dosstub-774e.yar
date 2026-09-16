rule TTP_XOR_MULT_DOSStub_774e {
  strings:
    $key_774e = { 23 26 [2] 57 3e [2] 10 3c [2] 57 2d [2] 19 21 [2] 15 2b [2] 02 20 [2] 19 6e [2] 24 }

  condition:
    any of them
}