rule TTP_XOR_MULT_DOSStub_557b {
  strings:
    $key_557b = { 01 13 [2] 75 0b [2] 32 09 [2] 75 18 [2] 3b 14 [2] 37 1e [2] 20 15 [2] 3b 5b [2] 06 }

  condition:
    any of them
}