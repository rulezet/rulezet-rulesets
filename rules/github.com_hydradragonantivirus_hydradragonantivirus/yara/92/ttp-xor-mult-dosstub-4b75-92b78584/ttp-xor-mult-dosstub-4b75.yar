rule TTP_XOR_MULT_DOSStub_4b75 {
  strings:
    $key_4b75 = { 1f 1d [2] 6b 05 [2] 2c 07 [2] 6b 16 [2] 25 1a [2] 29 10 [2] 3e 1b [2] 25 55 [2] 18 }

  condition:
    any of them
}