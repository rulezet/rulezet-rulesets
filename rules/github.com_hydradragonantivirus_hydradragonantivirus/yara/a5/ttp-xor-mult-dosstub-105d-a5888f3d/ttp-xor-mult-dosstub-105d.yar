rule TTP_XOR_MULT_DOSStub_105d {
  strings:
    $key_105d = { 44 35 [2] 30 2d [2] 77 2f [2] 30 3e [2] 7e 32 [2] 72 38 [2] 65 33 [2] 7e 7d [2] 43 }

  condition:
    any of them
}