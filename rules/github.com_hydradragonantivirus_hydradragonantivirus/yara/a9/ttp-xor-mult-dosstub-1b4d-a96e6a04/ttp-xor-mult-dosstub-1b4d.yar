rule TTP_XOR_MULT_DOSStub_1b4d {
  strings:
    $key_1b4d = { 4f 25 [2] 3b 3d [2] 7c 3f [2] 3b 2e [2] 75 22 [2] 79 28 [2] 6e 23 [2] 75 6d [2] 48 }

  condition:
    any of them
}