rule TTP_XOR_MULT_DOSStub_5678 {
  strings:
    $key_5678 = { 02 10 [2] 76 08 [2] 31 0a [2] 76 1b [2] 38 17 [2] 34 1d [2] 23 16 [2] 38 58 [2] 05 }

  condition:
    any of them
}