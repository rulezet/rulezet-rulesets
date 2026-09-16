rule TTP_XOR_MULT_DOSStub_785d {
  strings:
    $key_785d = { 2c 35 [2] 58 2d [2] 1f 2f [2] 58 3e [2] 16 32 [2] 1a 38 [2] 0d 33 [2] 16 7d [2] 2b }

  condition:
    any of them
}