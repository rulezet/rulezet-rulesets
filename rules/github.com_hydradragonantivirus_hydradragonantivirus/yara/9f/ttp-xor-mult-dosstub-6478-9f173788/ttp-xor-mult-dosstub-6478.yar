rule TTP_XOR_MULT_DOSStub_6478 {
  strings:
    $key_6478 = { 30 10 [2] 44 08 [2] 03 0a [2] 44 1b [2] 0a 17 [2] 06 1d [2] 11 16 [2] 0a 58 [2] 37 }

  condition:
    any of them
}