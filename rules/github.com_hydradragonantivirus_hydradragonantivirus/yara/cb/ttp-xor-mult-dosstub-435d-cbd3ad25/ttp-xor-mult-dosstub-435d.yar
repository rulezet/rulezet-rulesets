rule TTP_XOR_MULT_DOSStub_435d {
  strings:
    $key_435d = { 17 35 [2] 63 2d [2] 24 2f [2] 63 3e [2] 2d 32 [2] 21 38 [2] 36 33 [2] 2d 7d [2] 10 }

  condition:
    any of them
}