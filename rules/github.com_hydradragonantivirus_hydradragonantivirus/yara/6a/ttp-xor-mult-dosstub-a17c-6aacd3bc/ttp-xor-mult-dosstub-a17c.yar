rule TTP_XOR_MULT_DOSStub_a17c {
  strings:
    $key_a17c = { f5 14 [2] 81 0c [2] c6 0e [2] 81 1f [2] cf 13 [2] c3 19 [2] d4 12 [2] cf 5c [2] f2 }

  condition:
    any of them
}