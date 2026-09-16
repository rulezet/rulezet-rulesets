rule TTP_XOR_MULT_DOSStub_a151 {
  strings:
    $key_a151 = { f5 39 [2] 81 21 [2] c6 23 [2] 81 32 [2] cf 3e [2] c3 34 [2] d4 3f [2] cf 71 [2] f2 }

  condition:
    any of them
}