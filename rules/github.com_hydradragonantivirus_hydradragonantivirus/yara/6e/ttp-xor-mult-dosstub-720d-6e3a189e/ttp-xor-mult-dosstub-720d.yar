rule TTP_XOR_MULT_DOSStub_720d {
  strings:
    $key_720d = { 26 65 [2] 52 7d [2] 15 7f [2] 52 6e [2] 1c 62 [2] 10 68 [2] 07 63 [2] 1c 2d [2] 21 }

  condition:
    any of them
}