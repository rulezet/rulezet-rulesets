rule TTP_XOR_MULT_DOSStub_735d {
  strings:
    $key_735d = { 27 35 [2] 53 2d [2] 14 2f [2] 53 3e [2] 1d 32 [2] 11 38 [2] 06 33 [2] 1d 7d [2] 20 }

  condition:
    any of them
}