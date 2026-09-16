rule TTP_XOR_MULT_DOSStub_a1fc {
  strings:
    $key_a1fc = { f5 94 [2] 81 8c [2] c6 8e [2] 81 9f [2] cf 93 [2] c3 99 [2] d4 92 [2] cf dc [2] f2 }

  condition:
    any of them
}