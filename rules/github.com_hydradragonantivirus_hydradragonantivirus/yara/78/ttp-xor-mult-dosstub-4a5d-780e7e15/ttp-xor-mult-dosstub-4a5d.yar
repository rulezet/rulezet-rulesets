rule TTP_XOR_MULT_DOSStub_4a5d {
  strings:
    $key_4a5d = { 1e 35 [2] 6a 2d [2] 2d 2f [2] 6a 3e [2] 24 32 [2] 28 38 [2] 3f 33 [2] 24 7d [2] 19 }

  condition:
    any of them
}