rule TTP_XOR_MULT_DOSStub_520d {
  strings:
    $key_520d = { 06 65 [2] 72 7d [2] 35 7f [2] 72 6e [2] 3c 62 [2] 30 68 [2] 27 63 [2] 3c 2d [2] 01 }

  condition:
    any of them
}