rule TTP_XOR_MULT_DOSStub_f77e {
  strings:
    $key_f77e = { a3 16 [2] d7 0e [2] 90 0c [2] d7 1d [2] 99 11 [2] 95 1b [2] 82 10 [2] 99 5e [2] a4 }

  condition:
    any of them
}