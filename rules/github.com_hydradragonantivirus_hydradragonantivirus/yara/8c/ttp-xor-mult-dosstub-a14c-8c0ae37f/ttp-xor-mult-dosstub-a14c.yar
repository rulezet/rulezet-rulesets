rule TTP_XOR_MULT_DOSStub_a14c {
  strings:
    $key_a14c = { f5 24 [2] 81 3c [2] c6 3e [2] 81 2f [2] cf 23 [2] c3 29 [2] d4 22 [2] cf 6c [2] f2 }

  condition:
    any of them
}