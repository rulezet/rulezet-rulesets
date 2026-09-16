rule TTP_XOR_MULT_DOSStub_4c4d {
  strings:
    $key_4c4d = { 18 25 [2] 6c 3d [2] 2b 3f [2] 6c 2e [2] 22 22 [2] 2e 28 [2] 39 23 [2] 22 6d [2] 1f }

  condition:
    any of them
}