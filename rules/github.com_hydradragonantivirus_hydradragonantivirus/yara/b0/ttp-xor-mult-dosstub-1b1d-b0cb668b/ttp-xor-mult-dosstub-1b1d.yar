rule TTP_XOR_MULT_DOSStub_1b1d {
  strings:
    $key_1b1d = { 4f 75 [2] 3b 6d [2] 7c 6f [2] 3b 7e [2] 75 72 [2] 79 78 [2] 6e 73 [2] 75 3d [2] 48 }

  condition:
    any of them
}