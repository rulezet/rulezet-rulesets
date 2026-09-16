rule TTP_XOR_MULT_DOSStub_457d {
  strings:
    $key_457d = { 11 15 [2] 65 0d [2] 22 0f [2] 65 1e [2] 2b 12 [2] 27 18 [2] 30 13 [2] 2b 5d [2] 16 }

  condition:
    any of them
}