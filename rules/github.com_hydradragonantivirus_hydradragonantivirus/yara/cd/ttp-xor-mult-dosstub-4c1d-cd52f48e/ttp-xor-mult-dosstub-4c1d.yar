rule TTP_XOR_MULT_DOSStub_4c1d {
  strings:
    $key_4c1d = { 18 75 [2] 6c 6d [2] 2b 6f [2] 6c 7e [2] 22 72 [2] 2e 78 [2] 39 73 [2] 22 3d [2] 1f }

  condition:
    any of them
}