rule TTP_XOR_MULT_DOSStub_4dae {
  strings:
    $key_4dae = { 19 c6 [2] 6d de [2] 2a dc [2] 6d cd [2] 23 c1 [2] 2f cb [2] 38 c0 [2] 23 8e [2] 1e }

  condition:
    any of them
}