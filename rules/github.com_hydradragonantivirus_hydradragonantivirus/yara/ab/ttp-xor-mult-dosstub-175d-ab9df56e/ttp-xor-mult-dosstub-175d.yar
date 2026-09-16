rule TTP_XOR_MULT_DOSStub_175d {
  strings:
    $key_175d = { 43 35 [2] 37 2d [2] 70 2f [2] 37 3e [2] 79 32 [2] 75 38 [2] 62 33 [2] 79 7d [2] 44 }

  condition:
    any of them
}