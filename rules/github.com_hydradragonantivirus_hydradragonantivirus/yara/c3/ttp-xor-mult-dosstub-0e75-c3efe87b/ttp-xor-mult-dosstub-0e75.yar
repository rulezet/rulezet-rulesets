rule TTP_XOR_MULT_DOSStub_0e75 {
  strings:
    $key_0e75 = { 5a 1d [2] 2e 05 [2] 69 07 [2] 2e 16 [2] 60 1a [2] 6c 10 [2] 7b 1b [2] 60 55 [2] 5d }

  condition:
    any of them
}