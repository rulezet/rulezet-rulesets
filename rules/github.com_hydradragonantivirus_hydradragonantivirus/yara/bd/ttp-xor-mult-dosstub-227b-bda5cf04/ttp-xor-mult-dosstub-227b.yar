rule TTP_XOR_MULT_DOSStub_227b {
  strings:
    $key_227b = { 76 13 [2] 02 0b [2] 45 09 [2] 02 18 [2] 4c 14 [2] 40 1e [2] 57 15 [2] 4c 5b [2] 71 }

  condition:
    any of them
}