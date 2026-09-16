rule TTP_XOR_MULT_DOSStub_7a7b {
  strings:
    $key_7a7b = { 2e 13 [2] 5a 0b [2] 1d 09 [2] 5a 18 [2] 14 14 [2] 18 1e [2] 0f 15 [2] 14 5b [2] 29 }

  condition:
    any of them
}