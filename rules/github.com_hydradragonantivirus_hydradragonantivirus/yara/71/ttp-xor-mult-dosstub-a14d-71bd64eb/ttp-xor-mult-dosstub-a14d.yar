rule TTP_XOR_MULT_DOSStub_a14d {
  strings:
    $key_a14d = { f5 25 [2] 81 3d [2] c6 3f [2] 81 2e [2] cf 22 [2] c3 28 [2] d4 23 [2] cf 6d [2] f2 }

  condition:
    any of them
}