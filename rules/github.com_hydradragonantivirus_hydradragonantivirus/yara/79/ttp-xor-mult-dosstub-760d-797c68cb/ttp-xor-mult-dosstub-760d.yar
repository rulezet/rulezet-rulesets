rule TTP_XOR_MULT_DOSStub_760d {
  strings:
    $key_760d = { 22 65 [2] 56 7d [2] 11 7f [2] 56 6e [2] 18 62 [2] 14 68 [2] 03 63 [2] 18 2d [2] 25 }

  condition:
    any of them
}