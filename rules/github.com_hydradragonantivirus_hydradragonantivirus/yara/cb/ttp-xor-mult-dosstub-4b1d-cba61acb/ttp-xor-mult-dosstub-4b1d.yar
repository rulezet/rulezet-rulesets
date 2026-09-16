rule TTP_XOR_MULT_DOSStub_4b1d {
  strings:
    $key_4b1d = { 1f 75 [2] 6b 6d [2] 2c 6f [2] 6b 7e [2] 25 72 [2] 29 78 [2] 3e 73 [2] 25 3d [2] 18 }

  condition:
    any of them
}