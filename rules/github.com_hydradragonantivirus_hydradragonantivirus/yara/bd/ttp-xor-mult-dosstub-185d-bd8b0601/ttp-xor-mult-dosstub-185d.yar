rule TTP_XOR_MULT_DOSStub_185d {
  strings:
    $key_185d = { 4c 35 [2] 38 2d [2] 7f 2f [2] 38 3e [2] 76 32 [2] 7a 38 [2] 6d 33 [2] 76 7d [2] 4b }

  condition:
    any of them
}