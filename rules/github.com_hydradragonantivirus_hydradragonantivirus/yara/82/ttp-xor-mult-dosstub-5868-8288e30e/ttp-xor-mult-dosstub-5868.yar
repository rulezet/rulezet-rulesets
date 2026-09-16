rule TTP_XOR_MULT_DOSStub_5868 {
  strings:
    $key_5868 = { 0c 00 [2] 78 18 [2] 3f 1a [2] 78 0b [2] 36 07 [2] 3a 0d [2] 2d 06 [2] 36 48 [2] 0b }

  condition:
    any of them
}