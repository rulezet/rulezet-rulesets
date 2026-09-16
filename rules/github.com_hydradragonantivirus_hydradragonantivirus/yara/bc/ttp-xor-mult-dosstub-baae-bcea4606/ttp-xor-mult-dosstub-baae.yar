rule TTP_XOR_MULT_DOSStub_baae {
  strings:
    $key_baae = { ee c6 [2] 9a de [2] dd dc [2] 9a cd [2] d4 c1 [2] d8 cb [2] cf c0 [2] d4 8e [2] e9 }

  condition:
    any of them
}