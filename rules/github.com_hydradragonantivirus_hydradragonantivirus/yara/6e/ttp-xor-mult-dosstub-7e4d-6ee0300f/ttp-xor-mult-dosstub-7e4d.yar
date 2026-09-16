rule TTP_XOR_MULT_DOSStub_7e4d {
  strings:
    $key_7e4d = { 2a 25 [2] 5e 3d [2] 19 3f [2] 5e 2e [2] 10 22 [2] 1c 28 [2] 0b 23 [2] 10 6d [2] 2d }

  condition:
    any of them
}