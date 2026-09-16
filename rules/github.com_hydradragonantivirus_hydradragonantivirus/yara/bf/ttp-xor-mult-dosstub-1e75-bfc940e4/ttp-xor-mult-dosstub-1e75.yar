rule TTP_XOR_MULT_DOSStub_1e75 {
  strings:
    $key_1e75 = { 4a 1d [2] 3e 05 [2] 79 07 [2] 3e 16 [2] 70 1a [2] 7c 10 [2] 6b 1b [2] 70 55 [2] 4d }

  condition:
    any of them
}