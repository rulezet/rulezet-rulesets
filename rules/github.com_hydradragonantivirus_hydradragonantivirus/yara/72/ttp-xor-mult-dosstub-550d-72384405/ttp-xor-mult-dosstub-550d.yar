rule TTP_XOR_MULT_DOSStub_550d {
  strings:
    $key_550d = { 01 65 [2] 75 7d [2] 32 7f [2] 75 6e [2] 3b 62 [2] 37 68 [2] 20 63 [2] 3b 2d [2] 06 }

  condition:
    any of them
}