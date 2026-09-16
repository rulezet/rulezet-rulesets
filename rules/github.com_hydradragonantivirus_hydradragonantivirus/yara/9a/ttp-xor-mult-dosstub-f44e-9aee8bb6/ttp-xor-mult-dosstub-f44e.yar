rule TTP_XOR_MULT_DOSStub_f44e {
  strings:
    $key_f44e = { a0 26 [2] d4 3e [2] 93 3c [2] d4 2d [2] 9a 21 [2] 96 2b [2] 81 20 [2] 9a 6e [2] a7 }

  condition:
    any of them
}