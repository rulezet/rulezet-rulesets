rule TTP_XOR_MULT_DOSStub_740d {
  strings:
    $key_740d = { 20 65 [2] 54 7d [2] 13 7f [2] 54 6e [2] 1a 62 [2] 16 68 [2] 01 63 [2] 1a 2d [2] 27 }

  condition:
    any of them
}