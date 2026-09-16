rule TTP_XOR_MULT_DOSStub_225d {
  strings:
    $key_225d = { 76 35 [2] 02 2d [2] 45 2f [2] 02 3e [2] 4c 32 [2] 40 38 [2] 57 33 [2] 4c 7d [2] 71 }

  condition:
    any of them
}