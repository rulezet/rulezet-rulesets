rule TTP_XOR_MULT_DOSStub_6e3a {
  strings:
    $key_6e3a = { 3a 52 [2] 4e 4a [2] 09 48 [2] 4e 59 [2] 00 55 [2] 0c 5f [2] 1b 54 [2] 00 1a [2] 3d }

  condition:
    any of them
}