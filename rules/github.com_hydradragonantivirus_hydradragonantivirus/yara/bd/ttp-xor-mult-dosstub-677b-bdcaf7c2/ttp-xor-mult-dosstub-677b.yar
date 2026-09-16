rule TTP_XOR_MULT_DOSStub_677b {
  strings:
    $key_677b = { 33 13 [2] 47 0b [2] 00 09 [2] 47 18 [2] 09 14 [2] 05 1e [2] 12 15 [2] 09 5b [2] 34 }

  condition:
    any of them
}