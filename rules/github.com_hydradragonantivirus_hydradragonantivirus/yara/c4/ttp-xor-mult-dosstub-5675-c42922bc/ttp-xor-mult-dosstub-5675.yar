rule TTP_XOR_MULT_DOSStub_5675 {
  strings:
    $key_5675 = { 02 1d [2] 76 05 [2] 31 07 [2] 76 16 [2] 38 1a [2] 34 10 [2] 23 1b [2] 38 55 [2] 05 }

  condition:
    any of them
}