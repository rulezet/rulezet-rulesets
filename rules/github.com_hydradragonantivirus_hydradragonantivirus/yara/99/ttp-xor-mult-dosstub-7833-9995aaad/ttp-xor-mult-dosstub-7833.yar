rule TTP_XOR_MULT_DOSStub_7833 {
  strings:
    $key_7833 = { 2c 5b [2] 58 43 [2] 1f 41 [2] 58 50 [2] 16 5c [2] 1a 56 [2] 0d 5d [2] 16 13 [2] 2b }

  condition:
    any of them
}