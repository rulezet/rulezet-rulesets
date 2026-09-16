rule TTP_XOR_MULT_DOSStub_743d {
  strings:
    $key_743d = { 20 55 [2] 54 4d [2] 13 4f [2] 54 5e [2] 1a 52 [2] 16 58 [2] 01 53 [2] 1a 1d [2] 27 }

  condition:
    any of them
}