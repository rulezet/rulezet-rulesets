rule TTP_XOR_MULT_DOSStub_751b {
  strings:
    $key_751b = { 21 73 [2] 55 6b [2] 12 69 [2] 55 78 [2] 1b 74 [2] 17 7e [2] 00 75 [2] 1b 3b [2] 26 }

  condition:
    any of them
}