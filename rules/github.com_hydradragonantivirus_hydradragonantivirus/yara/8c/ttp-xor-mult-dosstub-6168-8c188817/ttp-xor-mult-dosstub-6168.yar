rule TTP_XOR_MULT_DOSStub_6168 {
  strings:
    $key_6168 = { 35 00 [2] 41 18 [2] 06 1a [2] 41 0b [2] 0f 07 [2] 03 0d [2] 14 06 [2] 0f 48 [2] 32 }

  condition:
    any of them
}