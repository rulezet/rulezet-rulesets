rule TTP_XOR_MULT_DOSStub_054e {
  strings:
    $key_054e = { 51 26 [2] 25 3e [2] 62 3c [2] 25 2d [2] 6b 21 [2] 67 2b [2] 70 20 [2] 6b 6e [2] 56 }

  condition:
    any of them
}