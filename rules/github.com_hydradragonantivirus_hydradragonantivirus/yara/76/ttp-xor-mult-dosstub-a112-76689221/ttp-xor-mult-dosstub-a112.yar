rule TTP_XOR_MULT_DOSStub_a112 {
  strings:
    $key_a112 = { f5 7a [2] 81 62 [2] c6 60 [2] 81 71 [2] cf 7d [2] c3 77 [2] d4 7c [2] cf 32 [2] f2 }

  condition:
    any of them
}