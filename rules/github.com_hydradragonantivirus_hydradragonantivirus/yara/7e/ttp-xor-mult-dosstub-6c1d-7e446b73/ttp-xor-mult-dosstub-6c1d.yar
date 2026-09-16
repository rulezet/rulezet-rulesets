rule TTP_XOR_MULT_DOSStub_6c1d {
  strings:
    $key_6c1d = { 38 75 [2] 4c 6d [2] 0b 6f [2] 4c 7e [2] 02 72 [2] 0e 78 [2] 19 73 [2] 02 3d [2] 3f }

  condition:
    any of them
}