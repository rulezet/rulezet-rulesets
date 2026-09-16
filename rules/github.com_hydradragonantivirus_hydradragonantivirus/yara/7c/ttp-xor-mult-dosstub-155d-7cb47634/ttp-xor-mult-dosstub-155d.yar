rule TTP_XOR_MULT_DOSStub_155d {
  strings:
    $key_155d = { 41 35 [2] 35 2d [2] 72 2f [2] 35 3e [2] 7b 32 [2] 77 38 [2] 60 33 [2] 7b 7d [2] 46 }

  condition:
    any of them
}