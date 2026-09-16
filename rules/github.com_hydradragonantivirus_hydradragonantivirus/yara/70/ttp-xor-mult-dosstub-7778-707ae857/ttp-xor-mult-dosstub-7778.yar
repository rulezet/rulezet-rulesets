rule TTP_XOR_MULT_DOSStub_7778 {
  strings:
    $key_7778 = { 23 10 [2] 57 08 [2] 10 0a [2] 57 1b [2] 19 17 [2] 15 1d [2] 02 16 [2] 19 58 [2] 24 }

  condition:
    any of them
}