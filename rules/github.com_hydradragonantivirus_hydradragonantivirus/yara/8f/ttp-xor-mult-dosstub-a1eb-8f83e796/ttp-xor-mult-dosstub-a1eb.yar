rule TTP_XOR_MULT_DOSStub_a1eb {
  strings:
    $key_a1eb = { f5 83 [2] 81 9b [2] c6 99 [2] 81 88 [2] cf 84 [2] c3 8e [2] d4 85 [2] cf cb [2] f2 }

  condition:
    any of them
}