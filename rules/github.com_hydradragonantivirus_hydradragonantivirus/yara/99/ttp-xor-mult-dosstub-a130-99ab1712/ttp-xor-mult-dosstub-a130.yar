rule TTP_XOR_MULT_DOSStub_a130 {
  strings:
    $key_a130 = { f5 58 [2] 81 40 [2] c6 42 [2] 81 53 [2] cf 5f [2] c3 55 [2] d4 5e [2] cf 10 [2] f2 }

  condition:
    any of them
}