rule TTP_XOR_MULT_DOSStub_055d {
  strings:
    $key_055d = { 51 35 [2] 25 2d [2] 62 2f [2] 25 3e [2] 6b 32 [2] 67 38 [2] 70 33 [2] 6b 7d [2] 56 }

  condition:
    any of them
}