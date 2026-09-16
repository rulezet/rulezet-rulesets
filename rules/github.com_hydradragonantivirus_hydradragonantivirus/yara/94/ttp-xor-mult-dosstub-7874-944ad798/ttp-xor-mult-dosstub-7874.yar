rule TTP_XOR_MULT_DOSStub_7874 {
  strings:
    $key_7874 = { 2c 1c [2] 58 04 [2] 1f 06 [2] 58 17 [2] 16 1b [2] 1a 11 [2] 0d 1a [2] 16 54 [2] 2b }

  condition:
    any of them
}