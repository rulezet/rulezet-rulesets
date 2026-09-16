rule TTP_XOR_MULT_DOSStub_235d {
  strings:
    $key_235d = { 77 35 [2] 03 2d [2] 44 2f [2] 03 3e [2] 4d 32 [2] 41 38 [2] 56 33 [2] 4d 7d [2] 70 }

  condition:
    any of them
}