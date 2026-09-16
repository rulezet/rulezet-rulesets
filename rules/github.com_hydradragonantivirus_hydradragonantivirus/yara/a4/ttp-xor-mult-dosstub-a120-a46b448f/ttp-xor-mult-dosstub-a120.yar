rule TTP_XOR_MULT_DOSStub_a120 {
  strings:
    $key_a120 = { f5 48 [2] 81 50 [2] c6 52 [2] 81 43 [2] cf 4f [2] c3 45 [2] d4 4e [2] cf 00 [2] f2 }

  condition:
    any of them
}