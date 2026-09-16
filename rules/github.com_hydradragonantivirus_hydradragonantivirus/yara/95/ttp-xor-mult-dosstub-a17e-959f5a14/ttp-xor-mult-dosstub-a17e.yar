rule TTP_XOR_MULT_DOSStub_a17e {
  strings:
    $key_a17e = { f5 16 [2] 81 0e [2] c6 0c [2] 81 1d [2] cf 11 [2] c3 1b [2] d4 10 [2] cf 5e [2] f2 }

  condition:
    any of them
}