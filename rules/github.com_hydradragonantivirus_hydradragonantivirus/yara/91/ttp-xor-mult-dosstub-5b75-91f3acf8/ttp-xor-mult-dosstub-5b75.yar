rule TTP_XOR_MULT_DOSStub_5b75 {
  strings:
    $key_5b75 = { 0f 1d [2] 7b 05 [2] 3c 07 [2] 7b 16 [2] 35 1a [2] 39 10 [2] 2e 1b [2] 35 55 [2] 08 }

  condition:
    any of them
}