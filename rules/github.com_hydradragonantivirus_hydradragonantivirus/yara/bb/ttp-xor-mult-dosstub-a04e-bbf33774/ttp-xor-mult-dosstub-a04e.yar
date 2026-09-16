rule TTP_XOR_MULT_DOSStub_a04e {
  strings:
    $key_a04e = { f4 26 [2] 80 3e [2] c7 3c [2] 80 2d [2] ce 21 [2] c2 2b [2] d5 20 [2] ce 6e [2] f3 }

  condition:
    any of them
}