rule TTP_XOR_MULT_DOSStub_a12e {
  strings:
    $key_a12e = { f5 46 [2] 81 5e [2] c6 5c [2] 81 4d [2] cf 41 [2] c3 4b [2] d4 40 [2] cf 0e [2] f2 }

  condition:
    any of them
}