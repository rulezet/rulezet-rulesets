rule TTP_XOR_MULT_DOSStub_6c4d {
  strings:
    $key_6c4d = { 38 25 [2] 4c 3d [2] 0b 3f [2] 4c 2e [2] 02 22 [2] 0e 28 [2] 19 23 [2] 02 6d [2] 3f }

  condition:
    any of them
}