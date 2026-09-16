rule TTP_XOR_MULT_DOSStub_374d {
  strings:
    $key_374d = { 63 25 [2] 17 3d [2] 50 3f [2] 17 2e [2] 59 22 [2] 55 28 [2] 42 23 [2] 59 6d [2] 64 }

  condition:
    any of them
}