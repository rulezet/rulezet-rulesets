rule TTP_XOR_MULT_DOSStub_4778 {
  strings:
    $key_4778 = { 13 10 [2] 67 08 [2] 20 0a [2] 67 1b [2] 29 17 [2] 25 1d [2] 32 16 [2] 29 58 [2] 14 }

  condition:
    any of them
}