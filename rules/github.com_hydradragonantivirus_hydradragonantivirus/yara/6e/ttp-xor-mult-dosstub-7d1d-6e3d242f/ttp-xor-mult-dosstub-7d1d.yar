rule TTP_XOR_MULT_DOSStub_7d1d {
  strings:
    $key_7d1d = { 29 75 [2] 5d 6d [2] 1a 6f [2] 5d 7e [2] 13 72 [2] 1f 78 [2] 08 73 [2] 13 3d [2] 2e }

  condition:
    any of them
}