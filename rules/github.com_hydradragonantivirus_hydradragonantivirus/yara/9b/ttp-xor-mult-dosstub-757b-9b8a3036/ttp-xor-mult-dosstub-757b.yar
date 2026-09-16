rule TTP_XOR_MULT_DOSStub_757b {
  strings:
    $key_757b = { 21 13 [2] 55 0b [2] 12 09 [2] 55 18 [2] 1b 14 [2] 17 1e [2] 00 15 [2] 1b 5b [2] 26 }

  condition:
    any of them
}