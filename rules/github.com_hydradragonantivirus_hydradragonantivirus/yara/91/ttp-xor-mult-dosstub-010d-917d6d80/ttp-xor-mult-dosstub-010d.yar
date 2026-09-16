rule TTP_XOR_MULT_DOSStub_010d {
  strings:
    $key_010d = { 55 65 [2] 21 7d [2] 66 7f [2] 21 6e [2] 6f 62 [2] 63 68 [2] 74 63 [2] 6f 2d [2] 52 }

  condition:
    any of them
}