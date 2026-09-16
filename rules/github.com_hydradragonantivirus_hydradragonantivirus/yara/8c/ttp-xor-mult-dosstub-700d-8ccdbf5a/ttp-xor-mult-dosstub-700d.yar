rule TTP_XOR_MULT_DOSStub_700d {
  strings:
    $key_700d = { 24 65 [2] 50 7d [2] 17 7f [2] 50 6e [2] 1e 62 [2] 12 68 [2] 05 63 [2] 1e 2d [2] 23 }

  condition:
    any of them
}