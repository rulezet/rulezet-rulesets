rule TTP_XOR_MULT_DOSStub_6778 {
  strings:
    $key_6778 = { 33 10 [2] 47 08 [2] 00 0a [2] 47 1b [2] 09 17 [2] 05 1d [2] 12 16 [2] 09 58 [2] 34 }

  condition:
    any of them
}