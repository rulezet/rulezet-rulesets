rule TTP_XOR_MULT_DOSStub_630d {
  strings:
    $key_630d = { 37 65 [2] 43 7d [2] 04 7f [2] 43 6e [2] 0d 62 [2] 01 68 [2] 16 63 [2] 0d 2d [2] 30 }

  condition:
    any of them
}