rule TTP_XOR_MULT_DOSStub_7e1d {
  strings:
    $key_7e1d = { 2a 75 [2] 5e 6d [2] 19 6f [2] 5e 7e [2] 10 72 [2] 1c 78 [2] 0b 73 [2] 10 3d [2] 2d }

  condition:
    any of them
}