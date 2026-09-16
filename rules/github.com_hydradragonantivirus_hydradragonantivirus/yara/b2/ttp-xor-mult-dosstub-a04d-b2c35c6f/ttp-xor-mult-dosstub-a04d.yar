rule TTP_XOR_MULT_DOSStub_a04d {
  strings:
    $key_a04d = { f4 25 [2] 80 3d [2] c7 3f [2] 80 2e [2] ce 22 [2] c2 28 [2] d5 23 [2] ce 6d [2] f3 }

  condition:
    any of them
}