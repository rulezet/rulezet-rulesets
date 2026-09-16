rule TTP_XOR_MULT_DOSStub_a07e {
  strings:
    $key_a07e = { f4 16 [2] 80 0e [2] c7 0c [2] 80 1d [2] ce 11 [2] c2 1b [2] d5 10 [2] ce 5e [2] f3 }

  condition:
    any of them
}