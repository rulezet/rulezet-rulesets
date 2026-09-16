rule TTP_XOR_MULT_DOSStub_260d {
  strings:
    $key_260d = { 72 65 [2] 06 7d [2] 41 7f [2] 06 6e [2] 48 62 [2] 44 68 [2] 53 63 [2] 48 2d [2] 75 }

  condition:
    any of them
}