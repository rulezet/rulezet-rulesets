rule TTP_XOR_MULT_DOSStub_f47e {
  strings:
    $key_f47e = { a0 16 [2] d4 0e [2] 93 0c [2] d4 1d [2] 9a 11 [2] 96 1b [2] 81 10 [2] 9a 5e [2] a7 }

  condition:
    any of them
}