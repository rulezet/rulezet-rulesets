rule TTP_XOR_MULT_DOSStub_1575 {
  strings:
    $key_1575 = { 41 1d [2] 35 05 [2] 72 07 [2] 35 16 [2] 7b 1a [2] 77 10 [2] 60 1b [2] 7b 55 [2] 46 }

  condition:
    any of them
}