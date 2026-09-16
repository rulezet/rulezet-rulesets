rule TTP_XOR_MULT_DOSStub_a01d {
  strings:
    $key_a01d = { f4 75 [2] 80 6d [2] c7 6f [2] 80 7e [2] ce 72 [2] c2 78 [2] d5 73 [2] ce 3d [2] f3 }

  condition:
    any of them
}