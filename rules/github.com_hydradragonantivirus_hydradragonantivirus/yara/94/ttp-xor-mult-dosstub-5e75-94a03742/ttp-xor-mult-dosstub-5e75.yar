rule TTP_XOR_MULT_DOSStub_5e75 {
  strings:
    $key_5e75 = { 0a 1d [2] 7e 05 [2] 39 07 [2] 7e 16 [2] 30 1a [2] 3c 10 [2] 2b 1b [2] 30 55 [2] 0d }

  condition:
    any of them
}