rule TTP_XOR_MULT_DOSStub_5065 {
  strings:
    $key_5065 = { 04 0d [2] 70 15 [2] 37 17 [2] 70 06 [2] 3e 0a [2] 32 00 [2] 25 0b [2] 3e 45 [2] 03 }

  condition:
    any of them
}