rule TTP_XOR_MULT_DOSStub_a127 {
  strings:
    $key_a127 = { f5 4f [2] 81 57 [2] c6 55 [2] 81 44 [2] cf 48 [2] c3 42 [2] d4 49 [2] cf 07 [2] f2 }

  condition:
    any of them
}