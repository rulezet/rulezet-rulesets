rule TTP_XOR_MULT_DOSStub_7b75 {
  strings:
    $key_7b75 = { 2f 1d [2] 5b 05 [2] 1c 07 [2] 5b 16 [2] 15 1a [2] 19 10 [2] 0e 1b [2] 15 55 [2] 28 }

  condition:
    any of them
}