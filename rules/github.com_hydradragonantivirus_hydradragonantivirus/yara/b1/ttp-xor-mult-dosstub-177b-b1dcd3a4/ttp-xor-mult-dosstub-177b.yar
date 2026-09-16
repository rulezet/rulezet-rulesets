rule TTP_XOR_MULT_DOSStub_177b {
  strings:
    $key_177b = { 43 13 [2] 37 0b [2] 70 09 [2] 37 18 [2] 79 14 [2] 75 1e [2] 62 15 [2] 79 5b [2] 44 }

  condition:
    any of them
}