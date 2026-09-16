rule TTP_XOR_MULT_DOSStub_69a3 {
  strings:
    $key_69a3 = { 3d cb [2] 49 d3 [2] 0e d1 [2] 49 c0 [2] 07 cc [2] 0b c6 [2] 1c cd [2] 07 83 [2] 3a }

  condition:
    any of them
}