rule TTP_XOR_MULT_DOSStub_154d {
  strings:
    $key_154d = { 41 25 [2] 35 3d [2] 72 3f [2] 35 2e [2] 7b 22 [2] 77 28 [2] 60 23 [2] 7b 6d [2] 46 }

  condition:
    any of them
}