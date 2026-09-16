rule TTP_XOR_MULT_DOSStub_6e3d {
  strings:
    $key_6e3d = { 3a 55 [2] 4e 4d [2] 09 4f [2] 4e 5e [2] 00 52 [2] 0c 58 [2] 1b 53 [2] 00 1d [2] 3d }

  condition:
    any of them
}