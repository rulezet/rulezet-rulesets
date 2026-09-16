rule TTP_XOR_MULT_DOSStub_7965 {
  strings:
    $key_7965 = { 2d 0d [2] 59 15 [2] 1e 17 [2] 59 06 [2] 17 0a [2] 1b 00 [2] 0c 0b [2] 17 45 [2] 2a }

  condition:
    any of them
}