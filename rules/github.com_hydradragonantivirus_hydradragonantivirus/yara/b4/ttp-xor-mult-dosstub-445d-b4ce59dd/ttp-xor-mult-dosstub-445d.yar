rule TTP_XOR_MULT_DOSStub_445d {
  strings:
    $key_445d = { 10 35 [2] 64 2d [2] 23 2f [2] 64 3e [2] 2a 32 [2] 26 38 [2] 31 33 [2] 2a 7d [2] 17 }

  condition:
    any of them
}