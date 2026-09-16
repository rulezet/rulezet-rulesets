rule TTP_XOR_MULT_DOSStub_1b75 {
  strings:
    $key_1b75 = { 4f 1d [2] 3b 05 [2] 7c 07 [2] 3b 16 [2] 75 1a [2] 79 10 [2] 6e 1b [2] 75 55 [2] 48 }

  condition:
    any of them
}