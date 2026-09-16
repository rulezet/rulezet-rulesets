rule TTP_XOR_MULT_DOSStub_6865 {
  strings:
    $key_6865 = { 3c 0d [2] 48 15 [2] 0f 17 [2] 48 06 [2] 06 0a [2] 0a 00 [2] 1d 0b [2] 06 45 [2] 3b }

  condition:
    any of them
}