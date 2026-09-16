rule TTP_XOR_MULT_DOSStub_6e5d {
  strings:
    $key_6e5d = { 3a 35 [2] 4e 2d [2] 09 2f [2] 4e 3e [2] 00 32 [2] 0c 38 [2] 1b 33 [2] 00 7d [2] 3d }

  condition:
    any of them
}