rule TTP_XOR_MULT_DOSStub_6e7a {
  strings:
    $key_6e7a = { 3a 12 [2] 4e 0a [2] 09 08 [2] 4e 19 [2] 00 15 [2] 0c 1f [2] 1b 14 [2] 00 5a [2] 3d }

  condition:
    any of them
}