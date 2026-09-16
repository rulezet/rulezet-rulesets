rule TTP_XOR_MULT_DOSStub_080d {
  strings:
    $key_080d = { 5c 65 [2] 28 7d [2] 6f 7f [2] 28 6e [2] 66 62 [2] 6a 68 [2] 7d 63 [2] 66 2d [2] 5b }

  condition:
    any of them
}