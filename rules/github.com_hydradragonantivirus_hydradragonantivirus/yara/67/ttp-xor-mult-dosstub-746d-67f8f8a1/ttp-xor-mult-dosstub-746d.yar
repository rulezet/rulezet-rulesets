rule TTP_XOR_MULT_DOSStub_746d {
  strings:
    $key_746d = { 20 05 [2] 54 1d [2] 13 1f [2] 54 0e [2] 1a 02 [2] 16 08 [2] 01 03 [2] 1a 4d [2] 27 }

  condition:
    any of them
}