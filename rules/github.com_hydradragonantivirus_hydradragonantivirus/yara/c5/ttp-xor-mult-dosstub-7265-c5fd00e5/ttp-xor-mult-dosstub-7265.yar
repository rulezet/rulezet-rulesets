rule TTP_XOR_MULT_DOSStub_7265 {
  strings:
    $key_7265 = { 26 0d [2] 52 15 [2] 15 17 [2] 52 06 [2] 1c 0a [2] 10 00 [2] 07 0b [2] 1c 45 [2] 21 }

  condition:
    any of them
}