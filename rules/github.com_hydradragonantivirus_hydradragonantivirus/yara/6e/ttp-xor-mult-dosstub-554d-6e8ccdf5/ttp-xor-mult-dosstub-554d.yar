rule TTP_XOR_MULT_DOSStub_554d {
  strings:
    $key_554d = { 01 25 [2] 75 3d [2] 32 3f [2] 75 2e [2] 3b 22 [2] 37 28 [2] 20 23 [2] 3b 6d [2] 06 }

  condition:
    any of them
}