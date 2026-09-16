rule TTP_XOR_MULT_DOSStub_6868 {
  strings:
    $key_6868 = { 3c 00 [2] 48 18 [2] 0f 1a [2] 48 0b [2] 06 07 [2] 0a 0d [2] 1d 06 [2] 06 48 [2] 3b }

  condition:
    any of them
}