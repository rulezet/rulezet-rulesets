rule TTP_XOR_MULT_DOSStub_6e2d {
  strings:
    $key_6e2d = { 3a 45 [2] 4e 5d [2] 09 5f [2] 4e 4e [2] 00 42 [2] 0c 48 [2] 1b 43 [2] 00 0d [2] 3d }

  condition:
    any of them
}