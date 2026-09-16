rule TTP_XOR_MULT_DOSStub_6e0a {
  strings:
    $key_6e0a = { 3a 62 [2] 4e 7a [2] 09 78 [2] 4e 69 [2] 00 65 [2] 0c 6f [2] 1b 64 [2] 00 2a [2] 3d }

  condition:
    any of them
}