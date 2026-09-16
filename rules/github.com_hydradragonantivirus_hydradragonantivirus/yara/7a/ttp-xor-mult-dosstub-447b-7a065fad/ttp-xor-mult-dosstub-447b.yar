rule TTP_XOR_MULT_DOSStub_447b {
  strings:
    $key_447b = { 10 13 [2] 64 0b [2] 23 09 [2] 64 18 [2] 2a 14 [2] 26 1e [2] 31 15 [2] 2a 5b [2] 17 }

  condition:
    any of them
}