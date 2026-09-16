rule TTP_XOR_MULT_DOSStub_2e75 {
  strings:
    $key_2e75 = { 7a 1d [2] 0e 05 [2] 49 07 [2] 0e 16 [2] 40 1a [2] 4c 10 [2] 5b 1b [2] 40 55 [2] 7d }

  condition:
    any of them
}