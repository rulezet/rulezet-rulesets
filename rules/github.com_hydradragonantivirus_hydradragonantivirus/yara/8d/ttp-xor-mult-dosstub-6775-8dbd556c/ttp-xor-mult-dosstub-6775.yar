rule TTP_XOR_MULT_DOSStub_6775 {
  strings:
    $key_6775 = { 33 1d [2] 47 05 [2] 00 07 [2] 47 16 [2] 09 1a [2] 05 10 [2] 12 1b [2] 09 55 [2] 34 }

  condition:
    any of them
}