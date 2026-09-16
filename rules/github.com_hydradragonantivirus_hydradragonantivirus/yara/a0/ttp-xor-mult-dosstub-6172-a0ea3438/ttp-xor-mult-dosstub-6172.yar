rule TTP_XOR_MULT_DOSStub_6172 {
  strings:
    $key_6172 = { 35 1a [2] 41 02 [2] 06 00 [2] 41 11 [2] 0f 1d [2] 03 17 [2] 14 1c [2] 0f 52 [2] 32 }

  condition:
    any of them
}