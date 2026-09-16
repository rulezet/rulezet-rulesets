rule TTP_XOR_MULT_DOSStub_5872 {
  strings:
    $key_5872 = { 0c 1a [2] 78 02 [2] 3f 00 [2] 78 11 [2] 36 1d [2] 3a 17 [2] 2d 1c [2] 36 52 [2] 0b }

  condition:
    any of them
}