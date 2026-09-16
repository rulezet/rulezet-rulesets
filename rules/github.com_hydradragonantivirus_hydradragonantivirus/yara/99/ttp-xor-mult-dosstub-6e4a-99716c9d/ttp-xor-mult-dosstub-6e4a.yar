rule TTP_XOR_MULT_DOSStub_6e4a {
  strings:
    $key_6e4a = { 3a 22 [2] 4e 3a [2] 09 38 [2] 4e 29 [2] 00 25 [2] 0c 2f [2] 1b 24 [2] 00 6a [2] 3d }

  condition:
    any of them
}