rule TTP_XOR_MULT_DOSStub_527b {
  strings:
    $key_527b = { 06 13 [2] 72 0b [2] 35 09 [2] 72 18 [2] 3c 14 [2] 30 1e [2] 27 15 [2] 3c 5b [2] 01 }

  condition:
    any of them
}