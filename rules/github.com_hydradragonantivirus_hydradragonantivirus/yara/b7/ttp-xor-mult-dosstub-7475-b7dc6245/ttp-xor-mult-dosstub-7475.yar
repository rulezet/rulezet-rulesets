rule TTP_XOR_MULT_DOSStub_7475 {
  strings:
    $key_7475 = { 20 1d [2] 54 05 [2] 13 07 [2] 54 16 [2] 1a 1a [2] 16 10 [2] 01 1b [2] 1a 55 [2] 27 }

  condition:
    any of them
}