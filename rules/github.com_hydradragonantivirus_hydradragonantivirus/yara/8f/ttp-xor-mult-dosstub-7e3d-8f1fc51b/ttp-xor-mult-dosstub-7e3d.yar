rule TTP_XOR_MULT_DOSStub_7e3d {
  strings:
    $key_7e3d = { 2a 55 [2] 5e 4d [2] 19 4f [2] 5e 5e [2] 10 52 [2] 1c 58 [2] 0b 53 [2] 10 1d [2] 2d }

  condition:
    any of them
}