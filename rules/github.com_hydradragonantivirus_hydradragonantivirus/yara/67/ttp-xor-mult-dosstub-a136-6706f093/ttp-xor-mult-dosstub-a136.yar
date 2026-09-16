rule TTP_XOR_MULT_DOSStub_a136 {
  strings:
    $key_a136 = { f5 5e [2] 81 46 [2] c6 44 [2] 81 55 [2] cf 59 [2] c3 53 [2] d4 58 [2] cf 16 [2] f2 }

  condition:
    any of them
}