rule TTP_XOR_MULT_DOSStub_715d {
  strings:
    $key_715d = { 25 35 [2] 51 2d [2] 16 2f [2] 51 3e [2] 1f 32 [2] 13 38 [2] 04 33 [2] 1f 7d [2] 22 }

  condition:
    any of them
}