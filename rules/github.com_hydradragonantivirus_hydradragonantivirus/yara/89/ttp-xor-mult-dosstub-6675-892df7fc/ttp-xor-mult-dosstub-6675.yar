rule TTP_XOR_MULT_DOSStub_6675 {
  strings:
    $key_6675 = { 32 1d [2] 46 05 [2] 01 07 [2] 46 16 [2] 08 1a [2] 04 10 [2] 13 1b [2] 08 55 [2] 35 }

  condition:
    any of them
}