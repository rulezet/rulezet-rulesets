rule TTP_XOR_MULT_DOSStub_6475 {
  strings:
    $key_6475 = { 30 1d [2] 44 05 [2] 03 07 [2] 44 16 [2] 0a 1a [2] 06 10 [2] 11 1b [2] 0a 55 [2] 37 }

  condition:
    any of them
}