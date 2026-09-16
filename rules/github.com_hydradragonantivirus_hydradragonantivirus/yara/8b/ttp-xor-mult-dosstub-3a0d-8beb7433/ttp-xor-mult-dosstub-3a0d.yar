rule TTP_XOR_MULT_DOSStub_3a0d {
  strings:
    $key_3a0d = { 6e 65 [2] 1a 7d [2] 5d 7f [2] 1a 6e [2] 54 62 [2] 58 68 [2] 4f 63 [2] 54 2d [2] 69 }

  condition:
    any of them
}