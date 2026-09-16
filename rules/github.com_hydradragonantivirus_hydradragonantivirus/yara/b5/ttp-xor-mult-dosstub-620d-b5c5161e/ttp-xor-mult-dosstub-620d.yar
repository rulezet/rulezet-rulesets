rule TTP_XOR_MULT_DOSStub_620d {
  strings:
    $key_620d = { 36 65 [2] 42 7d [2] 05 7f [2] 42 6e [2] 0c 62 [2] 00 68 [2] 17 63 [2] 0c 2d [2] 31 }

  condition:
    any of them
}