rule TTP_XOR_MULT_DOSStub_530d {
  strings:
    $key_530d = { 07 65 [2] 73 7d [2] 34 7f [2] 73 6e [2] 3d 62 [2] 31 68 [2] 26 63 [2] 3d 2d [2] 00 }

  condition:
    any of them
}