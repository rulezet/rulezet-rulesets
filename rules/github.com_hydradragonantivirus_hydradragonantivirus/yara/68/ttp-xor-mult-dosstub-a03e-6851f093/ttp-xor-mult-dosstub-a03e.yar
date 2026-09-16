rule TTP_XOR_MULT_DOSStub_a03e {
  strings:
    $key_a03e = { f4 56 [2] 80 4e [2] c7 4c [2] 80 5d [2] ce 51 [2] c2 5b [2] d5 50 [2] ce 1e [2] f3 }

  condition:
    any of them
}