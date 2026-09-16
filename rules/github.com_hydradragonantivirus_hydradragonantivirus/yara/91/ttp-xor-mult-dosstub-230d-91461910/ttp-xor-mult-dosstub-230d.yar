rule TTP_XOR_MULT_DOSStub_230d {
  strings:
    $key_230d = { 77 65 [2] 03 7d [2] 44 7f [2] 03 6e [2] 4d 62 [2] 41 68 [2] 56 63 [2] 4d 2d [2] 70 }

  condition:
    any of them
}