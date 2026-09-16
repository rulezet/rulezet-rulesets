rule TTP_XOR_MULT_DOSStub_1c1d {
  strings:
    $key_1c1d = { 48 75 [2] 3c 6d [2] 7b 6f [2] 3c 7e [2] 72 72 [2] 7e 78 [2] 69 73 [2] 72 3d [2] 4f }

  condition:
    any of them
}