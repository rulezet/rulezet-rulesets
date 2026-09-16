rule TTP_XOR_MULT_DOSStub_444e {
  strings:
    $key_444e = { 10 26 [2] 64 3e [2] 23 3c [2] 64 2d [2] 2a 21 [2] 26 2b [2] 31 20 [2] 2a 6e [2] 17 }

  condition:
    any of them
}