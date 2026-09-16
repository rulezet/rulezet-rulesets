rule TTP_XOR_MULT_DOSStub_710d {
  strings:
    $key_710d = { 25 65 [2] 51 7d [2] 16 7f [2] 51 6e [2] 1f 62 [2] 13 68 [2] 04 63 [2] 1f 2d [2] 22 }

  condition:
    any of them
}