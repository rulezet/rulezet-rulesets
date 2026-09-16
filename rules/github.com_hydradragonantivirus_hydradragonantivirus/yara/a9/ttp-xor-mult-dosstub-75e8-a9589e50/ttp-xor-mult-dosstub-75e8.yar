rule TTP_XOR_MULT_DOSStub_75e8 {
  strings:
    $key_75e8 = { 21 80 [2] 55 98 [2] 12 9a [2] 55 8b [2] 1b 87 [2] 17 8d [2] 00 86 [2] 1b c8 [2] 26 }

  condition:
    any of them
}