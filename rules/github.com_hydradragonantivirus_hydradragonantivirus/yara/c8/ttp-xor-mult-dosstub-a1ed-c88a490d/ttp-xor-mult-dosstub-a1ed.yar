rule TTP_XOR_MULT_DOSStub_a1ed {
  strings:
    $key_a1ed = { f5 85 [2] 81 9d [2] c6 9f [2] 81 8e [2] cf 82 [2] c3 88 [2] d4 83 [2] cf cd [2] f2 }

  condition:
    any of them
}