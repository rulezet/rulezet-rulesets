rule TTP_XOR_MULT_DOSStub_2565 {
  strings:
    $key_2565 = { 71 0d [2] 05 15 [2] 42 17 [2] 05 06 [2] 4b 0a [2] 47 00 [2] 50 0b [2] 4b 45 [2] 76 }

  condition:
    any of them
}