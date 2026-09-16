rule TTP_XOR_MULT_DOSStub_187b {
  strings:
    $key_187b = { 4c 13 [2] 38 0b [2] 7f 09 [2] 38 18 [2] 76 14 [2] 7a 1e [2] 6d 15 [2] 76 5b [2] 4b }

  condition:
    any of them
}