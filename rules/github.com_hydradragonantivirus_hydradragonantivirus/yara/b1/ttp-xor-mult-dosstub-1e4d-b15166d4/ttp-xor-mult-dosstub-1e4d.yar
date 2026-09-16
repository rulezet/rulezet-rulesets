rule TTP_XOR_MULT_DOSStub_1e4d {
  strings:
    $key_1e4d = { 4a 25 [2] 3e 3d [2] 79 3f [2] 3e 2e [2] 70 22 [2] 7c 28 [2] 6b 23 [2] 70 6d [2] 4d }

  condition:
    any of them
}