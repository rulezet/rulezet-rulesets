rule TTP_XOR_MULT_DOSStub_a12d {
  strings:
    $key_a12d = { f5 45 [2] 81 5d [2] c6 5f [2] 81 4e [2] cf 42 [2] c3 48 [2] d4 43 [2] cf 0d [2] f2 }

  condition:
    any of them
}