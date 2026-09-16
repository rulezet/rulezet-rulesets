rule TTP_XOR_MULT_DOSStub_a44d {
  strings:
    $key_a44d = { f0 25 [2] 84 3d [2] c3 3f [2] 84 2e [2] ca 22 [2] c6 28 [2] d1 23 [2] ca 6d [2] f7 }

  condition:
    any of them
}