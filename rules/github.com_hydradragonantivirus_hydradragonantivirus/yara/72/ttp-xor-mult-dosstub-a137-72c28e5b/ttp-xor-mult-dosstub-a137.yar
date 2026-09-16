rule TTP_XOR_MULT_DOSStub_a137 {
  strings:
    $key_a137 = { f5 5f [2] 81 47 [2] c6 45 [2] 81 54 [2] cf 58 [2] c3 52 [2] d4 59 [2] cf 17 [2] f2 }

  condition:
    any of them
}