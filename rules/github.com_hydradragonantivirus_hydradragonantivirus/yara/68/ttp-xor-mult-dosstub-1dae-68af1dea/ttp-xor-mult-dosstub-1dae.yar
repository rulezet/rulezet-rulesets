rule TTP_XOR_MULT_DOSStub_1dae {
  strings:
    $key_1dae = { 49 c6 [2] 3d de [2] 7a dc [2] 3d cd [2] 73 c1 [2] 7f cb [2] 68 c0 [2] 73 8e [2] 4e }

  condition:
    any of them
}