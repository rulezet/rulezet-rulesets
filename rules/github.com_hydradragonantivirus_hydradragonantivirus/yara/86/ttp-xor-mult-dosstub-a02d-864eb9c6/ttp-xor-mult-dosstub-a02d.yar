rule TTP_XOR_MULT_DOSStub_a02d {
  strings:
    $key_a02d = { f4 45 [2] 80 5d [2] c7 5f [2] 80 4e [2] ce 42 [2] c2 48 [2] d5 43 [2] ce 0d [2] f3 }

  condition:
    any of them
}