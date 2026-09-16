rule TTP_XOR_MULT_DOSStub_4478 {
  strings:
    $key_4478 = { 10 10 [2] 64 08 [2] 23 0a [2] 64 1b [2] 2a 17 [2] 26 1d [2] 31 16 [2] 2a 58 [2] 17 }

  condition:
    any of them
}