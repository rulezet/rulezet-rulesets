rule TTP_XOR_MULT_DOSStub_234e {
  strings:
    $key_234e = { 77 26 [2] 03 3e [2] 44 3c [2] 03 2d [2] 4d 21 [2] 41 2b [2] 56 20 [2] 4d 6e [2] 70 }

  condition:
    any of them
}