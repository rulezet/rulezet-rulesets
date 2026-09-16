rule TTP_XOR_MULT_DOSStub_a71d {
  strings:
    $key_a71d = { f3 75 [2] 87 6d [2] c0 6f [2] 87 7e [2] c9 72 [2] c5 78 [2] d2 73 [2] c9 3d [2] f4 }

  condition:
    any of them
}