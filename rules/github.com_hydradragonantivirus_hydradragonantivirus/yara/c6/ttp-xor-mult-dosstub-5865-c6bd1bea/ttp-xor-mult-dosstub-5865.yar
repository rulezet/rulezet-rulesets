rule TTP_XOR_MULT_DOSStub_5865 {
  strings:
    $key_5865 = { 0c 0d [2] 78 15 [2] 3f 17 [2] 78 06 [2] 36 0a [2] 3a 00 [2] 2d 0b [2] 36 45 [2] 0b }

  condition:
    any of them
}