rule TTP_XOR_MULT_DOSStub_6872 {
  strings:
    $key_6872 = { 3c 1a [2] 48 02 [2] 0f 00 [2] 48 11 [2] 06 1d [2] 0a 17 [2] 1d 1c [2] 06 52 [2] 3b }

  condition:
    any of them
}