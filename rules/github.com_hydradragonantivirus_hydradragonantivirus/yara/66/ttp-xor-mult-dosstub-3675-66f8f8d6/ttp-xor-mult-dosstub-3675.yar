rule TTP_XOR_MULT_DOSStub_3675 {
  strings:
    $key_3675 = { 62 1d [2] 16 05 [2] 51 07 [2] 16 16 [2] 58 1a [2] 54 10 [2] 43 1b [2] 58 55 [2] 65 }

  condition:
    any of them
}