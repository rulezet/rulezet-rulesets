rule TTP_XOR_MULT_DOSStub_a117 {
  strings:
    $key_a117 = { f5 7f [2] 81 67 [2] c6 65 [2] 81 74 [2] cf 78 [2] c3 72 [2] d4 79 [2] cf 37 [2] f2 }

  condition:
    any of them
}