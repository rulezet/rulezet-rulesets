rule TTP_XOR_MULT_DOSStub_450d {
  strings:
    $key_450d = { 11 65 [2] 65 7d [2] 22 7f [2] 65 6e [2] 2b 62 [2] 27 68 [2] 30 63 [2] 2b 2d [2] 16 }

  condition:
    any of them
}