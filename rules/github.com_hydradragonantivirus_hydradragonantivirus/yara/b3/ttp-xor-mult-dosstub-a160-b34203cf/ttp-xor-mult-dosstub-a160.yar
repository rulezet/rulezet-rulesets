rule TTP_XOR_MULT_DOSStub_a160 {
  strings:
    $key_a160 = { f5 08 [2] 81 10 [2] c6 12 [2] 81 03 [2] cf 0f [2] c3 05 [2] d4 0e [2] cf 40 [2] f2 }

  condition:
    any of them
}