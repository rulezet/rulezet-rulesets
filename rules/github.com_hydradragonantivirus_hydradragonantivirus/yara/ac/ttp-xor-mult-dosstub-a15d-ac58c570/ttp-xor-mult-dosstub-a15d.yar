rule TTP_XOR_MULT_DOSStub_a15d {
  strings:
    $key_a15d = { f5 35 [2] 81 2d [2] c6 2f [2] 81 3e [2] cf 32 [2] c3 38 [2] d4 33 [2] cf 7d [2] f2 }

  condition:
    any of them
}