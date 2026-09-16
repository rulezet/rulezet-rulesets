rule TTP_XOR_MULT_DOSStub_a100 {
  strings:
    $key_a100 = { f5 68 [2] 81 70 [2] c6 72 [2] 81 63 [2] cf 6f [2] c3 65 [2] d4 6e [2] cf 20 [2] f2 }

  condition:
    any of them
}