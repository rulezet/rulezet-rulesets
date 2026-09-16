rule TTP_XOR_MULT_DOSStub_507b {
  strings:
    $key_507b = { 04 13 [2] 70 0b [2] 37 09 [2] 70 18 [2] 3e 14 [2] 32 1e [2] 25 15 [2] 3e 5b [2] 03 }

  condition:
    any of them
}